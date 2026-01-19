# sentinel/ioc_extractor.py

"""
IOC (Indicator of Compromise) extraction engine for Script Sentinel.

Extracts various types of IOCs from script content including IP addresses,
domains, URLs, file hashes, email addresses, file paths, and registry keys.
"""

import re
from typing import Dict, List, Set, Optional, Tuple
from pathlib import Path
from .models import IOC


class IOCExtractor:
    """
    Extracts Indicators of Compromise from script content.
    
    Supports extraction of 10 IOC types:
    - IPv4 addresses
    - IPv6 addresses
    - Domain names
    - URLs
    - Email addresses
    - File hashes (MD5, SHA1, SHA256)
    - File paths
    - Registry keys
    
    Includes false positive mitigation through whitelisting and confidence scoring.
    """
    
    # Pre-compiled regex patterns for performance
    PATTERNS = {
        'ipv4': re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'ipv6': re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|'
            r'\b::(?:ffff:)?(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        'url': re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        ),
        'domain': re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        ),
        'email': re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'file_path_windows': re.compile(
            r'[A-Za-z]:\\(?:[^\s<>:"|?*\\]+\\)*[^\s<>:"|?*\\]+',
            re.IGNORECASE
        ),
        'file_path_unix': re.compile(
            r'/(?:[^\s<>"|?*\n]+/)*[^\s<>"|?*\n]+'
        ),
        'registry_key': re.compile(
            r'\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|'
            r'HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|HKEY_CURRENT_CONFIG|HKCC)'
            r'\\[^\s<>"|?*\n]+',
            re.IGNORECASE
        ),
    }
    
    # Whitelists for false positive reduction
    SAFE_IPS = {
        '0.0.0.0', '127.0.0.1', '255.255.255.255',
        '::1', '::',  # IPv6 localhost
    }
    
    SAFE_IP_RANGES = [
        (r'^10\.', 'Private network'),
        (r'^172\.(1[6-9]|2[0-9]|3[01])\.', 'Private network'),
        (r'^192\.168\.', 'Private network'),
        (r'^169\.254\.', 'Link-local'),
        (r'^224\.', 'Multicast'),
    ]
    
    SAFE_DOMAINS = {
        # Reserved domains (RFC 2606)
        'localhost', 'example.com', 'example.org', 'example.net',
        'test', 'invalid', 'local',

        # Major tech companies
        'microsoft.com', 'windows.com', 'windowsupdate.com', 'live.com', 'office.com',
        'office365.com', 'azure.com', 'azureedge.net', 'msn.com', 'visualstudio.com',
        'nuget.org', 'powershellgallery.com',
        'apple.com', 'icloud.com', 'apple-dns.net',
        'google.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com',
        'googlesource.com', 'google-analytics.com', 'googletagmanager.com',
        'youtube.com', 'ytimg.com',
        'amazon.com', 'amazonaws.com', 'aws.amazon.com', 'cloudfront.net',
        's3.amazonaws.com', 'elasticbeanstalk.com',
        'facebook.com', 'fbcdn.net', 'meta.com',

        # Development platforms
        'github.com', 'github.io', 'githubusercontent.com', 'ghcr.io', 'raw.githubusercontent.com',
        'gitlab.com', 'gitlab.io',
        'bitbucket.org', 'atlassian.com', 'atlassian.net',
        'stackoverflow.com', 'stackexchange.com', 'stackblitz.com',
        'codepen.io', 'codesandbox.io', 'replit.com',
        'vercel.app', 'vercel.com', 'netlify.app', 'netlify.com',
        'heroku.com', 'herokuapp.com',
        'digitalocean.com', 'do.co',
        'render.com', 'railway.app', 'fly.io',

        # Package registries
        'npmjs.com', 'npmjs.org', 'registry.npmjs.org', 'yarnpkg.com',
        'pypi.org', 'pypi.python.org', 'pythonhosted.org', 'python.org',
        'rubygems.org', 'ruby-lang.org',
        'crates.io', 'rust-lang.org',
        'pkg.go.dev', 'go.dev', 'golang.org',
        'packagist.org', 'getcomposer.org',
        'mvnrepository.com', 'maven.apache.org', 'repo1.maven.org',
        'cpan.org', 'metacpan.org',

        # CDNs and web infrastructure
        'cloudflare.com', 'cdnjs.cloudflare.com', 'cloudflare-dns.com',
        'jsdelivr.net', 'unpkg.com', 'esm.sh', 'esm.run',
        'bootstrapcdn.com', 'fontawesome.com', 'fonts.googleapis.com',
        'jquery.com', 'code.jquery.com',
        'akamai.net', 'akamaized.net', 'akamaihd.net',
        'fastly.net', 'fastly.com',

        # Documentation and standards
        'w3.org', 'w3schools.com', 'whatwg.org',
        'mozilla.org', 'developer.mozilla.org', 'mdn.io',
        'ietf.org', 'rfc-editor.org',
        'readthedocs.io', 'readthedocs.org', 'rtfd.io',
        'docs.rs', 'doc.rust-lang.org',

        # Linux distributions
        'ubuntu.com', 'archive.ubuntu.com', 'ppa.launchpad.net',
        'debian.org', 'deb.debian.org', 'ftp.debian.org',
        'fedoraproject.org', 'centos.org', 'redhat.com',
        'archlinux.org', 'alpinelinux.org',
        'kernel.org',

        # Container registries
        'docker.com', 'docker.io', 'hub.docker.com',
        'quay.io', 'gcr.io', 'k8s.gcr.io', 'registry.k8s.io',
        'mcr.microsoft.com', 'ecr.aws',

        # CI/CD and DevOps
        'circleci.com', 'travis-ci.org', 'travis-ci.com',
        'jenkins.io', 'jenkins-ci.org',
        'drone.io', 'buildkite.com', 'semaphoreci.com',
        'ansible.com', 'hashicorp.com', 'terraform.io',

        # Security tools (legitimate)
        'virustotal.com', 'malwarebytes.com', 'clamav.net',
        'snyk.io', 'sonarqube.org', 'sonarcloud.io',
        'dependabot.com', 'renovatebot.com',

        # Common utilities
        'curl.se', 'curl.haxx.se', 'wget.gnu.org', 'gnu.org',
        'sourceforge.net', 'sf.net',
        'apache.org', 'nginx.org', 'nginx.com',
        'json.org', 'yaml.org', 'xml.org',
    }
    
    # Common programming language namespaces/packages to exclude
    PROGRAMMING_NAMESPACES = {
        # .NET namespaces
        'system.', 'microsoft.', 'windows.', 'collections.', 'linq.',
        'threading.', 'diagnostics.', 'reflection.', 'runtime.',
        'interopservices.', 'componentmodel.', 'drawing.', 'forms.',
        'data.', 'xml.', 'web.', 'net.', 'io.', 'text.', 'security.',
        # Java packages
        'java.', 'javax.', 'org.apache.', 'com.google.', 'android.',
        # Python modules
        'os.path.', 'sys.', 'json.', 'datetime.', 're.', 'collections.',
        # JavaScript/Node.js
        'console.', 'process.', 'buffer.', 'stream.', 'events.',
        'document.', 'window.', 'navigator.', 'location.',
    }
    
    # Common method/property patterns that look like domains
    CODE_PATTERNS = [
        re.compile(r'\b[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\(', re.IGNORECASE),  # method calls
        re.compile(r'\b[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*\s*=', re.IGNORECASE),  # property assignments
        re.compile(r'\b[a-z_][a-z0-9_]*\.[A-Z][a-zA-Z0-9]*\b'),  # PascalCase properties/methods
    ]
    
    SAFE_PATHS = {
        '/dev/null', '/tmp', '/var/log', '/etc', '/usr/bin',
        'C:\\Windows', 'C:\\Program Files', 'C:\\Users',
    }
    
    # Suspicious keywords that increase IOC confidence
    SUSPICIOUS_KEYWORDS = {
        'download', 'invoke', 'execute', 'connect', 'request',
        'wget', 'curl', 'fetch', 'get-content', 'invoke-webrequest',
        'invoke-restmethod', 'start-bitstransfer', 'downloadstring',
        'downloadfile', 'webclient', 'httpclient',
    }
    
    def __init__(self):
        """Initialize the IOC extractor with compiled patterns."""
        # Patterns are already compiled as class variables
        pass
    
    def extract(
        self,
        script_content: str,
        language: str,
        findings: Optional[List] = None
    ) -> Dict[str, List[IOC]]:
        """
        Extract all IOCs from script content.
        
        Args:
            script_content: Raw script text to analyze.
            language: Script language (powershell, bash, javascript).
            findings: Optional list of existing findings (may contain IOCs).
            
        Returns:
            Dictionary mapping IOC types to lists of IOC objects.
            Keys: 'ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1',
                  'sha256', 'file_path', 'registry_key'
        """
        iocs: Dict[str, List[IOC]] = {}
        lines = script_content.splitlines()
        
        # Extract each IOC type
        iocs['ipv4'] = self._extract_ipv4(script_content, lines)
        iocs['ipv6'] = self._extract_ipv6(script_content, lines)
        iocs['url'] = self._extract_urls(script_content, lines)
        iocs['domain'] = self._extract_domains(script_content, lines, iocs['url'])
        iocs['email'] = self._extract_emails(script_content, lines)
        
        # Extract file hashes
        hash_iocs = self._extract_hashes(script_content, lines)
        iocs['md5'] = hash_iocs.get('md5', [])
        iocs['sha1'] = hash_iocs.get('sha1', [])
        iocs['sha256'] = hash_iocs.get('sha256', [])
        
        # Extract file paths and registry keys
        iocs['file_path'] = self._extract_file_paths(script_content, lines, language)
        iocs['registry_key'] = self._extract_registry_keys(script_content, lines)
        
        # Remove empty IOC types
        iocs = {k: v for k, v in iocs.items() if v}
        
        return iocs
    
    def _extract_ipv4(self, content: str, lines: List[str]) -> List[IOC]:
        """Extract IPv4 addresses with confidence scoring."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['ipv4'].finditer(line):
                ip = match.group(0)
                
                # Skip if already seen
                if ip in seen:
                    continue
                seen.add(ip)
                
                # Calculate confidence
                confidence = self._calculate_ip_confidence(ip, line)
                
                # Skip very low confidence IPs
                if confidence < 0.1:
                    continue
                
                iocs.append(IOC(
                    type='ipv4',
                    value=ip,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _extract_ipv6(self, content: str, lines: List[str]) -> List[IOC]:
        """Extract IPv6 addresses with confidence scoring."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['ipv6'].finditer(line):
                ip = match.group(0)
                
                if ip in seen or ip in self.SAFE_IPS:
                    continue
                seen.add(ip)
                
                confidence = 0.7 if self._is_suspicious_context(line) else 0.5
                
                iocs.append(IOC(
                    type='ipv6',
                    value=ip,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _extract_urls(self, content: str, lines: List[str]) -> List[IOC]:
        """Extract URLs with confidence scoring."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['url'].finditer(line):
                url = match.group(0)
                
                if url in seen:
                    continue
                seen.add(url)
                
                # Higher confidence for URLs in suspicious contexts
                confidence = 0.9 if self._is_suspicious_context(line) else 0.6
                
                # Lower confidence for URLs in comments
                if self._is_comment(line, language='powershell'):
                    confidence *= 0.5
                
                iocs.append(IOC(
                    type='url',
                    value=url,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _extract_domains(
        self,
        content: str,
        lines: List[str],
        url_iocs: List[IOC]
    ) -> List[IOC]:
        """Extract domain names, excluding those already in URLs."""
        iocs = []
        seen = set()
        
        # Extract domains from URLs first
        url_domains = set()
        for url_ioc in url_iocs:
            # Extract domain from URL
            domain_match = re.search(r'://([^/]+)', url_ioc.value)
            if domain_match:
                url_domains.add(domain_match.group(1).lower())
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['domain'].finditer(line):
                domain = match.group(0).lower()
                
                # Skip if already seen or in URL list or safe domain
                if (domain in seen or domain in url_domains or
                    domain in self.SAFE_DOMAINS):
                    continue
                
                # Skip programming language constructs
                if self._is_code_construct(domain, line):
                    continue
                    
                seen.add(domain)
                
                # Calculate confidence
                confidence = 0.7 if self._is_suspicious_context(line) else 0.4
                
                # Lower confidence for common TLDs in comments
                if self._is_comment(line, language='powershell'):
                    confidence *= 0.3
                
                if confidence < 0.2:
                    continue
                
                iocs.append(IOC(
                    type='domain',
                    value=domain,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _extract_emails(self, content: str, lines: List[str]) -> List[IOC]:
        """Extract email addresses."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['email'].finditer(line):
                email = match.group(0).lower()
                
                if email in seen:
                    continue
                seen.add(email)
                
                confidence = 0.8 if self._is_suspicious_context(line) else 0.5
                
                iocs.append(IOC(
                    type='email',
                    value=email,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _extract_hashes(
        self,
        content: str,
        lines: List[str]
    ) -> Dict[str, List[IOC]]:
        """Extract file hashes (MD5, SHA1, SHA256)."""
        hashes: Dict[str, List[IOC]] = {'md5': [], 'sha1': [], 'sha256': []}
        seen: Dict[str, Set[str]] = {'md5': set(), 'sha1': set(), 'sha256': set()}
        
        for line_num, line in enumerate(lines, 1):
            # Check each hash type
            for hash_type in ['sha256', 'sha1', 'md5']:  # Check longest first
                for match in self.PATTERNS[hash_type].finditer(line):
                    hash_value = match.group(0).lower()
                    
                    if hash_value in seen[hash_type]:
                        continue
                    seen[hash_type].add(hash_value)
                    
                    # High confidence for hashes in suspicious contexts
                    confidence = 0.9 if self._is_suspicious_context(line) else 0.7
                    
                    hashes[hash_type].append(IOC(
                        type=hash_type,
                        value=hash_value,
                        context=line.strip(),
                        line_number=line_num,
                        confidence=confidence
                    ))
        
        return hashes
    
    def _extract_file_paths(
        self,
        content: str,
        lines: List[str],
        language: str
    ) -> List[IOC]:
        """Extract file paths (Windows and Unix)."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            # Extract Windows paths
            for match in self.PATTERNS['file_path_windows'].finditer(line):
                path = match.group(0)
                
                if path in seen or any(path.startswith(safe) for safe in self.SAFE_PATHS):
                    continue
                seen.add(path)
                
                # Higher confidence for executable files
                confidence = 0.8 if path.lower().endswith(('.exe', '.dll', '.bat', '.ps1', '.vbs')) else 0.5
                
                iocs.append(IOC(
                    type='file_path',
                    value=path,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
            
            # Extract Unix paths (be more selective to avoid false positives)
            if language in ['bash', 'sh']:
                for match in self.PATTERNS['file_path_unix'].finditer(line):
                    path = match.group(0)
                    
                    # Skip very short paths or safe paths
                    if (len(path) < 5 or path in seen or 
                        any(path.startswith(safe) for safe in self.SAFE_PATHS)):
                        continue
                    seen.add(path)
                    
                    # Higher confidence for suspicious extensions
                    confidence = 0.7 if path.endswith(('.sh', '.py', '.pl', '.rb')) else 0.4
                    
                    if confidence < 0.3:
                        continue
                    
                    iocs.append(IOC(
                        type='file_path',
                        value=path,
                        context=line.strip(),
                        line_number=line_num,
                        confidence=confidence
                    ))
        
        return iocs
    
    def _extract_registry_keys(self, content: str, lines: List[str]) -> List[IOC]:
        """Extract Windows registry keys."""
        iocs = []
        seen = set()
        
        for line_num, line in enumerate(lines, 1):
            for match in self.PATTERNS['registry_key'].finditer(line):
                reg_key = match.group(0)
                
                if reg_key in seen:
                    continue
                seen.add(reg_key)
                
                # Higher confidence for suspicious registry locations
                confidence = 0.9 if any(sus in reg_key.lower() for sus in 
                    ['run', 'startup', 'currentversion\\windows', 'policies']) else 0.6
                
                iocs.append(IOC(
                    type='registry_key',
                    value=reg_key,
                    context=line.strip(),
                    line_number=line_num,
                    confidence=confidence
                ))
        
        return iocs
    
    def _calculate_ip_confidence(self, ip: str, context: str) -> float:
        """Calculate confidence score for an IP address."""
        # Start with base confidence
        confidence = 0.5
        
        # Check if it's a safe IP
        if ip in self.SAFE_IPS:
            return 0.1
        
        # Check if it's in a safe IP range
        for pattern, _ in self.SAFE_IP_RANGES:
            if re.match(pattern, ip):
                confidence = 0.2
                break
        
        # Increase confidence if in suspicious context
        if self._is_suspicious_context(context):
            confidence = min(1.0, confidence + 0.4)
        
        # Decrease confidence if in comment
        if self._is_comment(context, language='powershell'):
            confidence *= 0.3
        
        return confidence
    
    def _is_suspicious_context(self, line: str) -> bool:
        """Check if line contains suspicious keywords."""
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in self.SUSPICIOUS_KEYWORDS)
    
    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment."""
        stripped = line.strip()
        if language in ['powershell', 'bash', 'sh']:
            return stripped.startswith('#')
        elif language in ['javascript', 'js']:
            return stripped.startswith('//') or stripped.startswith('/*')
        return False
    
    def _is_code_construct(self, domain: str, context: str) -> bool:
        """
        Check if a domain-like string is actually a programming construct.
        
        Args:
            domain: The potential domain string
            context: The line context where it appears
            
        Returns:
            True if this appears to be code, not a real domain
        """
        # Check if it starts with a known programming namespace
        for namespace in self.PROGRAMMING_NAMESPACES:
            if domain.startswith(namespace):
                return True
        
        # Check if it appears in code patterns (method calls, property access, etc.)
        for pattern in self.CODE_PATTERNS:
            # Look for the domain in context with code patterns
            if pattern.search(context):
                # Check if our domain is part of this code pattern
                if domain in context.lower():
                    return True
        
        # Check for common code indicators in the context
        # Method calls with parentheses
        if re.search(rf'\b{re.escape(domain)}\s*\(', context, re.IGNORECASE):
            return True
        
        # Property/method chains (multiple dots in sequence)
        if re.search(rf'\b\w+\.{re.escape(domain)}\.', context, re.IGNORECASE):
            return True
        if re.search(rf'\b{re.escape(domain)}\.\w+\.', context, re.IGNORECASE):
            return True
        
        # Variable assignment patterns (var x = SomeClass.Property)
        if re.search(rf'=\s*{re.escape(domain)}\b', context, re.IGNORECASE):
            return True
        if re.search(rf'\b{re.escape(domain)}\s*;', context, re.IGNORECASE):
            return True
            
        # PascalCase or camelCase patterns typical in code
        parts = domain.split('.')
        if len(parts) >= 2:
            # Check if any part uses PascalCase (starts with capital)
            if any(part and part[0].isupper() for part in parts):
                return True
            
            # Check for common code patterns like os.path, sys.argv
            # (lowercase module.lowercase attribute)
            if all(part and part[0].islower() and part.isalnum() for part in parts):
                # If it's all lowercase alphanumeric parts, likely code
                # unless it looks like a real domain (has common TLD)
                common_tlds = {'com', 'org', 'net', 'io', 'dev', 'app', 'co'}
                if parts[-1] not in common_tlds:
                    return True
        
        return False