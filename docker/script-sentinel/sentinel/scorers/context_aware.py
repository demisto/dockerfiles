"""Context-aware scoring using heuristic analysis.

This module implements the ContextAwareScorer which analyzes script content
for contextual indicators to distinguish legitimate admin scripts from malware
without requiring pattern libraries or ML/LLM infrastructure.

Supports multi-language detection for PowerShell, Bash, and JavaScript.
"""

import re
from typing import Dict, Tuple, List, Any, Optional
from sentinel.scorers.base import BaseScorer


class ContextAwareScorer(BaseScorer):
    """
    Scores scripts based on contextual indicators without pattern libraries.

    Analyzes script characteristics to distinguish legitimate admin scripts
    from malware by detecting:
    - Legitimate indicators (documentation, user interaction, validation, logging, error handling)
    - Malicious indicators (hardcoded credentials, download+execute, user creation, security cascade, obfuscation)

    The scorer uses heuristic detection methods and operates deterministically
    without any ML/LLM dependencies. Supports PowerShell, Bash, and JavaScript.

    Attributes:
        config: Configuration dictionary from patterns_config.yaml
        enabled: Whether context-aware scoring is enabled
        doc_weight: Score adjustment for documentation (-20 points default)
        interaction_weight: Score adjustment for user interaction (-20 points default)
        validation_weight: Score adjustment for validation checks (-10 points default)
        logging_weight: Score adjustment for logging (-10 points default)
        error_weight: Score adjustment for error handling (-10 points default)
        hardcoded_creds_weight: Score adjustment for hardcoded credentials (+30 points default)
        download_exec_weight: Score adjustment for download+execute (+40 points default)
        user_creation_weight: Score adjustment for user creation (+30 points default)
        security_cascade_weight: Score adjustment for security cascade (+30 points default)
        obfuscation_weight: Score adjustment for obfuscation (+20 points default)

    Examples:
        >>> config = {
        ...     'context_aware_scoring': {
        ...         'enabled': True,
        ...         'legitimate_indicators': {
        ...             'documentation_weight': -20,
        ...             'user_interaction_weight': -20
        ...         }
        ...     }
        ... }
        >>> scorer = ContextAwareScorer(config)
        >>> score, explanations = scorer.score(script_content="test", language="bash")
        >>> 0 <= score <= 100
        True
    """

    # Default weight values (in points, 0-100 scale)
    DEFAULT_LEGITIMATE_WEIGHTS = {
        'documentation_weight': -20,
        'user_interaction_weight': -20,
        'validation_weight': -10,
        'logging_weight': -10,
        'error_handling_weight': -10,
        'network_config_weight': -10,
        'progress_indicators_weight': -5,
        'remote_management_weight': -10,
        'package_management_weight': -15,
        'build_tools_weight': -15,
        'testing_framework_weight': -15,
    }

    DEFAULT_MALICIOUS_WEIGHTS = {
        'hardcoded_credentials_weight': 30,
        'download_execute_weight': 40,
        'user_creation_weight': 30,
        'security_cascade_weight': 30,
        'obfuscation_weight': 20,
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize context-aware scorer.

        Args:
            config: Configuration dictionary with context_aware_scoring section
        """
        super().__init__(config)

        # Extract context-aware scoring configuration
        self.config = config.get('context_aware_scoring', {})
        self.enabled = self.config.get('enabled', False)

        # Load legitimate indicator weights with defaults
        legit = self.config.get('legitimate_indicators', {})
        self.doc_weight = legit.get('documentation_weight',
                                    self.DEFAULT_LEGITIMATE_WEIGHTS['documentation_weight'])
        self.interaction_weight = legit.get('user_interaction_weight',
                                           self.DEFAULT_LEGITIMATE_WEIGHTS['user_interaction_weight'])
        self.validation_weight = legit.get('validation_weight',
                                          self.DEFAULT_LEGITIMATE_WEIGHTS['validation_weight'])
        self.logging_weight = legit.get('logging_weight',
                                       self.DEFAULT_LEGITIMATE_WEIGHTS['logging_weight'])
        self.error_weight = legit.get('error_handling_weight',
                                     self.DEFAULT_LEGITIMATE_WEIGHTS['error_handling_weight'])
        self.network_config_weight = legit.get('network_config_weight',
                                              self.DEFAULT_LEGITIMATE_WEIGHTS['network_config_weight'])
        self.progress_weight = legit.get('progress_indicators_weight',
                                        self.DEFAULT_LEGITIMATE_WEIGHTS['progress_indicators_weight'])
        self.remote_mgmt_weight = legit.get('remote_management_weight',
                                           self.DEFAULT_LEGITIMATE_WEIGHTS['remote_management_weight'])
        self.package_mgmt_weight = legit.get('package_management_weight',
                                            self.DEFAULT_LEGITIMATE_WEIGHTS['package_management_weight'])
        self.build_tools_weight = legit.get('build_tools_weight',
                                           self.DEFAULT_LEGITIMATE_WEIGHTS['build_tools_weight'])
        self.testing_weight = legit.get('testing_framework_weight',
                                       self.DEFAULT_LEGITIMATE_WEIGHTS['testing_framework_weight'])

        # Load malicious indicator weights with defaults
        malicious = self.config.get('malicious_indicators', {})
        self.hardcoded_creds_weight = malicious.get('hardcoded_credentials_weight',
                                                    self.DEFAULT_MALICIOUS_WEIGHTS['hardcoded_credentials_weight'])
        self.download_exec_weight = malicious.get('download_execute_weight',
                                                  self.DEFAULT_MALICIOUS_WEIGHTS['download_execute_weight'])
        self.user_creation_weight = malicious.get('user_creation_weight',
                                                  self.DEFAULT_MALICIOUS_WEIGHTS['user_creation_weight'])
        self.security_cascade_weight = malicious.get('security_cascade_weight',
                                                     self.DEFAULT_MALICIOUS_WEIGHTS['security_cascade_weight'])
        self.obfuscation_weight = malicious.get('obfuscation_weight',
                                               self.DEFAULT_MALICIOUS_WEIGHTS['obfuscation_weight'])

    # =========================================================================
    # LANGUAGE DETECTION
    # =========================================================================

    def _detect_language(self, script_content: str) -> str:
        """
        Auto-detect script language from content.

        Args:
            script_content: Script text to analyze

        Returns:
            Detected language: 'powershell', 'bash', 'javascript', or 'unknown'
        """
        # Check for PowerShell indicators
        if re.search(r'\$\w+\s*=|\bfunction\s+\w+-\w+|Get-\w+|Set-\w+|New-\w+|\[Parameter\(',
                     script_content, re.IGNORECASE):
            return 'powershell'

        # Check for Bash shebang or common patterns
        if re.search(r'^#!\s*/(?:usr/)?bin/(?:ba)?sh|^#!\s*/usr/bin/env\s+(?:ba)?sh',
                     script_content, re.MULTILINE):
            return 'bash'
        if re.search(r'\bfi\b|\bdone\b|\besac\b|\$\{?\w+\}?|\[\[.*\]\]', script_content):
            return 'bash'

        # Check for JavaScript indicators
        if re.search(r'\bconst\s+\w+\s*=|\blet\s+\w+\s*=|\bfunction\s+\w+\s*\(|=>\s*\{|require\s*\(|import\s+.*from',
                     script_content):
            return 'javascript'

        return 'unknown'

    # =========================================================================
    # LEGITIMATE INDICATORS - POWERSHELL
    # =========================================================================

    def detect_documentation_powershell(self, script_content: str) -> bool:
        """Check for PowerShell documentation patterns."""
        return bool(re.search(
            r'\.SYNOPSIS|\.DESCRIPTION|\.NOTES|\.PARAMETER|\.EXAMPLE|'
            r'<#[\s\S]*?#>|#\s*(?:Author|Version|Date|Description):',
            script_content,
            re.IGNORECASE
        ))

    def detect_user_interaction_powershell(self, script_content: str) -> bool:
        """Check for PowerShell user interaction patterns."""
        return bool(re.search(
            r'Get-Credential|Read-Host|Out-GridView\s+-PassThru|'
            r'Show-Command|\$host\.UI\.Prompt',
            script_content,
            re.IGNORECASE
        ))

    def detect_validation_powershell(self, script_content: str) -> bool:
        """Check for PowerShell validation patterns."""
        return bool(re.search(
            r'Test-Connection|Test-Path|Test-NetConnection|'
            r'\[ValidateNotNullOrEmpty\]|\[ValidateScript\]|\[ValidateSet\]|'
            r'if\s*\(\s*\$\w+\s*-(?:eq|ne|gt|lt|like|match)',
            script_content,
            re.IGNORECASE
        ))

    def detect_logging_powershell(self, script_content: str) -> bool:
        """Check for PowerShell logging patterns."""
        return bool(re.search(
            r'Write-(?:Host|Verbose|Output|Information|Warning|Error|Debug)|'
            r'Out-File|Add-Content|Start-Transcript|'
            r'\$VerbosePreference|\$DebugPreference',
            script_content,
            re.IGNORECASE
        ))

    def detect_error_handling_powershell(self, script_content: str) -> bool:
        """Check for PowerShell error handling patterns."""
        return bool(re.search(
            r'try\s*\{|catch\s*\{|finally\s*\{|\$Error\b|\$\?|'
            r'-ErrorAction\s+(?:Stop|SilentlyContinue|Continue)|'
            r'\$ErrorActionPreference|trap\s*\{',
            script_content,
            re.IGNORECASE
        ))

    def detect_network_config_powershell(self, script_content: str) -> bool:
        """Check for PowerShell network configuration patterns."""
        return bool(re.search(
            r'Get-NetAdapter|Set-DnsClientServerAddress|Get-NetIPAddress|'
            r'New-NetIPAddress|Set-NetIPInterface|Get-NetFirewallRule|'
            r'Get-DnsClient|Set-NetFirewallProfile|Get-NetRoute',
            script_content,
            re.IGNORECASE
        ))

    def detect_remote_management_powershell(self, script_content: str) -> bool:
        """Check for PowerShell remote management patterns."""
        return bool(re.search(
            r'Invoke-Command\s+-ComputerName|Enter-PSSession|New-PSSession|'
            r'Test-WSMan|New-CimSession|Get-CimInstance|'
            r'Get-WmiObject|Invoke-WmiMethod',
            script_content,
            re.IGNORECASE
        ))

    def detect_package_management_powershell(self, script_content: str) -> bool:
        """Check for PowerShell package management patterns."""
        return bool(re.search(
            r'Install-Module|Install-Package|Find-Module|'
            r'Import-Module|Get-Module|Update-Module|'
            r'Register-PSRepository|Install-Script|'
            r'choco\s+install|winget\s+install|scoop\s+install',
            script_content,
            re.IGNORECASE
        ))

    # =========================================================================
    # LEGITIMATE INDICATORS - BASH
    # =========================================================================

    def detect_documentation_bash(self, script_content: str) -> bool:
        """Check for Bash documentation patterns."""
        return bool(re.search(
            r'^#\s*(?:Description|Usage|Author|Version|License|Copyright|Note|Purpose|Example):|'
            r'^#\s*[-=]{3,}|'  # Comment separator lines (# === or # ---)
            r'^#{4,}\s*$|'  # Hash separator lines (####)
            r'^#\s*\*{3,}|'  # Asterisk separator lines (# ***)
            r'^:\s*<<[\'"]?(?:EOF|END|DOC|HELP)[\'"]?|'  # Heredoc comments
            r'usage\s*\(\s*\)|show_help\s*\(\s*\)|print_usage\s*\(\s*\)|'
            r'^\s*#\s*@\w+\s',  # Annotation comments (# @param, # @author)
            script_content,
            re.MULTILINE | re.IGNORECASE
        ))

    def detect_shebang_bash(self, script_content: str) -> bool:
        """Check for proper Bash shebang."""
        return bool(re.search(
            r'^#!\s*/(?:usr/)?bin/(?:ba)?sh|^#!\s*/usr/bin/env\s+(?:ba)?sh',
            script_content,
            re.MULTILINE
        ))

    def detect_user_interaction_bash(self, script_content: str) -> bool:
        """Check for Bash user interaction patterns."""
        return bool(re.search(
            r'\bread\s+-[rep]*\s+\w+|'  # read command with prompts
            r'\bselect\s+\w+\s+in\b|'  # select menu
            r'\bdialog\b|\bzenity\b|\bkdialog\b|\bwhiptail\b|'  # GUI dialogs
            r'read\s+-p\s*["\']',
            script_content,
            re.IGNORECASE
        ))

    def detect_validation_bash(self, script_content: str) -> bool:
        """Check for Bash validation patterns."""
        return bool(re.search(
            r'\[\[\s+-[defrsxz]\s+|'  # File/string tests
            r'\btest\s+-[defrsxz]\s+|'  # test command
            r'\bcommand\s+-v\b|\bwhich\b|\btype\s+-[pt]\b|'  # Command existence
            r'if\s+\[\[?\s+.*\s+\]\]?\s*;?\s*then|'  # if statements
            r'\$\{\w+:[-+?]',
            script_content
        ))

    def detect_logging_bash(self, script_content: str) -> bool:
        """Check for Bash logging patterns."""
        # Check for structured logging patterns first
        structured_logging = bool(re.search(
            r'\blogger\b.*(?:-t|-p)|'  # syslog logger
            r'echo\s+.*>>\s*(?:/var/log/|\$[A-Z_]+_LOG|\$\{?log)|'  # Append to log file/variable
            r'exec\s+\d*>\s*>\s*\S+\.log|'  # File descriptor redirection
            r'\bprintf\b.*%[sdf]|'  # Formatted output (printf with format specifiers)
            r'echo\s+["\'][\[(].*["\']|'  # Timestamped/bracketed messages
            r'log_(?:info|warn|error|debug|msg)\s*[\("]|'  # Custom log functions
            r'\becho\s+["\']\s*\*{3,}|'  # Echo with emphasis (*** Starting...)
            r'\becho\s+["\']-{3,}',  # Echo with separators (--- Section ---)
            script_content,
            re.IGNORECASE
        ))
        if structured_logging:
            return True

        # Also detect scripts with many echo statements (>10) indicating verbose output
        echo_count = len(re.findall(r'\becho\s+["\']', script_content, re.IGNORECASE))
        return echo_count >= 10

    def detect_error_handling_bash(self, script_content: str) -> bool:
        """Check for Bash error handling patterns."""
        return bool(re.search(
            r'\bset\s+-[euxo]+|set\s+-o\s+(?:errexit|nounset|pipefail)|'  # Strict mode
            r'\btrap\b.*(?:ERR|EXIT|INT|TERM)|'  # Signal traps
            r'\|\|\s*(?:exit|return|die|error)|'  # Error handling chains
            r'if\s+!\s+|'  # Negated conditions
            r'\$\?|\$PIPESTATUS',
            script_content
        ))

    def detect_package_management_bash(self, script_content: str) -> bool:
        """Check for Bash package management patterns."""
        return bool(re.search(
            r'\bapt(?:-get)?\s+(?:install|update|upgrade)|'
            r'\byum\s+(?:install|update)|'
            r'\bdnf\s+(?:install|update)|'
            r'\bpacman\s+-S|'
            r'\bbrew\s+install|'
            r'\bpip3?\s+install|'
            r'\bnpm\s+install|'
            r'\byarn\s+add|'
            r'\bgem\s+install|'
            r'\bcargo\s+install|'
            r'\bgo\s+get|go\s+install',
            script_content,
            re.IGNORECASE
        ))

    def detect_build_tools_bash(self, script_content: str) -> bool:
        """Check for Bash build/CI tools patterns."""
        return bool(re.search(
            r'\bmake\b|\bcmake\b|\bgcc\b|\bg\+\+\b|'
            r'\bdocker\b.*(?:build|run|compose)|'
            r'\bkubectl\b|\bhelm\b|\bterraform\b|'
            r'\bansible(?:-playbook)?\b|'
            r'\bgradle\b|\bmvn\b|\bant\b|'
            r'\bbazel\b|\bninja\b|'
            r'CI=true|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|'
            r'\.github/workflows|\.gitlab-ci\.yml',
            script_content,
            re.IGNORECASE
        ))

    def detect_testing_bash(self, script_content: str) -> bool:
        """Check for Bash testing framework patterns."""
        return bool(re.search(
            r'\bbats\b|\bshunit2\b|\bbash_unit\b|'
            r'@test\s+["\']|'  # Bats test syntax
            r'assert_\w+|assertEquals|assertTrue|'
            r'\bpytest\b|\bjest\b|\bmocha\b|\brspec\b|'
            r'make\s+test|npm\s+test|yarn\s+test',
            script_content,
            re.IGNORECASE
        ))

    def detect_service_management_bash(self, script_content: str) -> bool:
        """Check for Bash service management patterns."""
        return bool(re.search(
            r'\bsystemctl\s+(?:start|stop|restart|enable|status)|'
            r'\bservice\s+\w+\s+(?:start|stop|restart)|'
            r'\bsupervisorctl\b|'
            r'\binitctl\b|'
            r'/etc/init\.d/',
            script_content,
            re.IGNORECASE
        ))

    # =========================================================================
    # LEGITIMATE INDICATORS - JAVASCRIPT
    # =========================================================================

    def detect_documentation_javascript(self, script_content: str) -> bool:
        """Check for JavaScript documentation patterns."""
        return bool(re.search(
            r'/\*\*[\s\S]*?@(?:param|returns?|description|example|author|version)|'  # JSDoc
            r'//\s*(?:TODO|FIXME|NOTE|XXX|HACK):|'  # Annotation comments
            r'/\*\*[\s\S]*?\*/|'  # Block comments
            r'@flow|@typescript',
            script_content
        ))

    def detect_user_interaction_javascript(self, script_content: str) -> bool:
        """Check for JavaScript user interaction patterns."""
        return bool(re.search(
            r'\bprompt\s*\(|\bconfirm\s*\(|\balert\s*\(|'
            r'readline\.question|inquirer\.|'
            r'addEventListener\s*\(\s*["\'](?:click|submit|input)|'
            r'\.on\s*\(\s*["\'](?:click|submit|data)\b',
            script_content
        ))

    def detect_validation_javascript(self, script_content: str) -> bool:
        """Check for JavaScript validation patterns."""
        return bool(re.search(
            r'typeof\s+\w+\s*[!=]==|'
            r'instanceof\s+\w+|'
            r'\.hasOwnProperty\s*\(|'
            r'Array\.isArray\s*\(|'
            r'if\s*\(\s*!?\w+\s*\)|'  # Truthy/falsy checks
            r'\.validate\s*\(|joi\.|yup\.|zod\.',
            script_content
        ))

    def detect_logging_javascript(self, script_content: str) -> bool:
        """Check for JavaScript logging patterns."""
        return bool(re.search(
            r'console\.(?:log|warn|error|info|debug|trace)\s*\(|'
            r'\blogger\.\w+\s*\(|'
            r'winston\.|bunyan\.|pino\.|'
            r'debug\s*\(\s*["\']',
            script_content
        ))

    def detect_error_handling_javascript(self, script_content: str) -> bool:
        """Check for JavaScript error handling patterns."""
        return bool(re.search(
            r'\btry\s*\{|\bcatch\s*\(\s*\w+\s*\)\s*\{|\bfinally\s*\{|'
            r'\.catch\s*\(|'
            r'Promise\.reject|'
            r'throw\s+new\s+\w*Error|'
            r'process\.on\s*\(\s*["\']uncaughtException',
            script_content
        ))

    def detect_package_management_javascript(self, script_content: str) -> bool:
        """Check for JavaScript package management patterns."""
        return bool(re.search(
            r'\brequire\s*\(\s*["\'][^"\']+["\']\s*\)|'
            r'\bimport\s+.*\s+from\s+["\']|'
            r'package\.json|'
            r'node_modules|'
            r'npm\s+(?:install|run)|'
            r'yarn\s+(?:add|run)|'
            r'pnpm\s+(?:add|run)',
            script_content
        ))

    def detect_testing_javascript(self, script_content: str) -> bool:
        """Check for JavaScript testing framework patterns."""
        return bool(re.search(
            r'\bdescribe\s*\(\s*["\']|\bit\s*\(\s*["\']|\btest\s*\(\s*["\']|'
            r'\bexpect\s*\(|\bassert\.|'
            r'jest\.|mocha\.|chai\.|jasmine\.|'
            r'@jest/|@testing-library/',
            script_content
        ))

    def detect_framework_javascript(self, script_content: str) -> bool:
        """Check for JavaScript framework patterns (React, Vue, Angular, Express)."""
        return bool(re.search(
            r'React\.|ReactDOM\.|useState|useEffect|'
            r'Vue\.|createApp|defineComponent|'
            r'@angular/|@Component|'
            r'express\s*\(\)|app\.(?:get|post|use)\s*\(|'
            r'next/|gatsby|nuxt',
            script_content
        ))

    # =========================================================================
    # MALICIOUS INDICATORS - MULTI-LANGUAGE
    # =========================================================================

    def detect_hardcoded_credentials(self, script_content: str, language: str = 'unknown') -> bool:
        """Check for hardcoded credentials across languages."""
        # PowerShell specific
        ps_creds = re.search(
            r'ConvertTo-SecureString.*-AsPlainText',
            script_content,
            re.IGNORECASE
        )

        # Generic patterns for all languages
        generic_creds = re.search(
            r'(?:password|passwd|pwd|secret|api_key|apikey|token)\s*[=:]\s*["\'][^"\']{4,}["\']|'
            r'Authorization:\s*(?:Basic|Bearer)\s+[A-Za-z0-9+/=]{10,}',
            script_content,
            re.IGNORECASE
        )

        return bool(ps_creds or generic_creds)

    def detect_download_execute(self, script_content: str, language: str = 'unknown') -> bool:
        """Check for download + execute patterns across languages."""
        # Download indicators
        has_download = bool(re.search(
            r'Invoke-WebRequest|DownloadFile|DownloadData|'
            r'\bwget\b|\bcurl\b.*-[oO]|'
            r'fetch\s*\(|axios\.|http\.get|'
            r'urllib\.request|requests\.get',
            script_content,
            re.IGNORECASE
        ))

        # Execute indicators
        has_execute = bool(re.search(
            r'Start-Process|Invoke-Expression|\biex\b|'
            r'\beval\s*\(|\bexec\s*\(|'
            r'\bsh\s+-c\b|\bbash\s+-c\b|'
            r'child_process|spawn\s*\(|'
            r'subprocess\.(?:run|call|Popen)|'
            r'\|\s*(?:ba)?sh\b',
            script_content,
            re.IGNORECASE
        ))

        return has_download and has_execute

    def detect_user_creation(self, script_content: str, language: str = 'unknown') -> bool:
        """Check for user creation commands across languages."""
        return bool(re.search(
            r'net\s+user.*\/add|New-LocalUser|'
            r'\buseradd\b|\badduser\b|'
            r'usermod\s+-aG\s+(?:sudo|wheel|admin)|'
            r'net\s+localgroup\s+administrators',
            script_content,
            re.IGNORECASE
        ))

    def detect_security_cascade(self, script_content: str, language: str = 'unknown') -> bool:
        """Check for multiple security disabling actions across languages."""
        patterns = [
            # PowerShell/Windows
            r'Set-NetFirewallProfile.*-Enabled\s+(?:False|\$false)',
            r'Set-MpPreference.*-Disable',
            r'EnableLUA.*0',
            r'DisableAntiSpyware.*1',
            r'netsh.*firewall.*(?:off|disable)',
            # Linux
            r'setenforce\s+0',
            r'ufw\s+disable',
            r'iptables\s+-F',
            r'systemctl\s+(?:stop|disable)\s+(?:firewalld|apparmor|selinux)',
            # AppArmor/SELinux
            r'aa-complain|aa-disable',
        ]
        matches = sum(1 for p in patterns if re.search(p, script_content, re.IGNORECASE))
        return matches >= 2

    def detect_obfuscation(self, script_content: str, language: str = 'unknown') -> bool:
        """Check for obfuscation techniques across languages."""
        patterns = [
            # Shortened paths
            r'[a-z]+~\d',
            # Base64 encoding
            r'FromBase64|ToBase64|\batob\s*\(|\bbtoa\s*\(',
            # Heavy string concatenation (5+ short strings)
            r'(?:["\'][^"\']{1,3}["\']\s*\+\s*){4,}',
            # Char code arrays
            r'String\.fromCharCode\s*\([^)]{20,}\)|'
            r'chr\s*\(\s*\d+\s*\)\s*\.\s*chr',
            # Hex/octal escapes
            r'(?:\\x[0-9a-f]{2}){5,}|(?:\\[0-7]{3}){5,}',
            # Variable-based command building
            r'\$\w+\s*\+\s*\$\w+\s*\+\s*\$\w+',
        ]

        matches = sum(1 for p in patterns if re.search(p, script_content, re.IGNORECASE))
        return matches >= 1

    # =========================================================================
    # MAIN SCORING FUNCTION
    # =========================================================================

    def score(self, script_content: str = None, base_score: float = 30.0,
              language: Optional[str] = None, **kwargs) -> Tuple[float, List[str]]:
        """
        Calculate context-aware score.

        Args:
            script_content: Script text to analyze
            base_score: Starting score before context adjustments (0-100 scale)
            language: Script language ('powershell', 'bash', 'javascript').
                     Auto-detected if not provided.
            **kwargs: Additional parameters (reserved for future use)

        Returns:
            Tuple of (adjusted_score: 0-100, explanations: list of strings)
        """
        # Handle missing script content
        if not script_content:
            return 0.0, ["No script content to analyze for context-aware scoring"]

        # Auto-detect language if not provided
        if not language or language == 'unknown':
            language = self._detect_language(script_content)
        language = language.lower()

        score = base_score
        explanations = []
        legitimate_indicators = []
        malicious_indicators = []
        adjustments = []

        # =====================================================================
        # LEGITIMATE INDICATORS (reduce score)
        # =====================================================================

        # Documentation detection (all languages)
        doc_detected = False
        if language == 'powershell':
            doc_detected = self.detect_documentation_powershell(script_content)
        elif language == 'bash':
            doc_detected = self.detect_documentation_bash(script_content)
        elif language == 'javascript':
            doc_detected = self.detect_documentation_javascript(script_content)

        if doc_detected:
            score += self.doc_weight
            legitimate_indicators.append('Documentation present')
            adjustments.append(f'{self.doc_weight:+.0f} (documentation)')

        # Shebang for Bash (strong legitimacy indicator)
        if language == 'bash' and self.detect_shebang_bash(script_content):
            score += -5  # Small bonus for proper shebang
            legitimate_indicators.append('Proper shebang')
            adjustments.append('-5 (shebang)')

        # User interaction detection
        interaction_detected = False
        if language == 'powershell':
            interaction_detected = self.detect_user_interaction_powershell(script_content)
        elif language == 'bash':
            interaction_detected = self.detect_user_interaction_bash(script_content)
        elif language == 'javascript':
            interaction_detected = self.detect_user_interaction_javascript(script_content)

        if interaction_detected:
            score += self.interaction_weight
            legitimate_indicators.append('User interaction required')
            adjustments.append(f'{self.interaction_weight:+.0f} (user interaction)')

        # Validation detection
        validation_detected = False
        if language == 'powershell':
            validation_detected = self.detect_validation_powershell(script_content)
        elif language == 'bash':
            validation_detected = self.detect_validation_bash(script_content)
        elif language == 'javascript':
            validation_detected = self.detect_validation_javascript(script_content)

        if validation_detected:
            score += self.validation_weight
            legitimate_indicators.append('Validation checks present')
            adjustments.append(f'{self.validation_weight:+.0f} (validation)')

        # Logging detection
        logging_detected = False
        if language == 'powershell':
            logging_detected = self.detect_logging_powershell(script_content)
        elif language == 'bash':
            logging_detected = self.detect_logging_bash(script_content)
        elif language == 'javascript':
            logging_detected = self.detect_logging_javascript(script_content)

        if logging_detected:
            score += self.logging_weight
            legitimate_indicators.append('Logging/output present')
            adjustments.append(f'{self.logging_weight:+.0f} (logging)')

        # Error handling detection
        error_detected = False
        if language == 'powershell':
            error_detected = self.detect_error_handling_powershell(script_content)
        elif language == 'bash':
            error_detected = self.detect_error_handling_bash(script_content)
        elif language == 'javascript':
            error_detected = self.detect_error_handling_javascript(script_content)

        if error_detected:
            score += self.error_weight
            legitimate_indicators.append('Error handling present')
            adjustments.append(f'{self.error_weight:+.0f} (error handling)')

        # Network configuration (PowerShell specific)
        if language == 'powershell' and self.detect_network_config_powershell(script_content):
            score += self.network_config_weight
            legitimate_indicators.append('Network configuration present')
            adjustments.append(f'{self.network_config_weight:+.0f} (network config)')

        # Remote management (PowerShell specific)
        if language == 'powershell' and self.detect_remote_management_powershell(script_content):
            score += self.remote_mgmt_weight
            legitimate_indicators.append('Remote management present')
            adjustments.append(f'{self.remote_mgmt_weight:+.0f} (remote management)')

        # Service management (Bash specific)
        if language == 'bash' and self.detect_service_management_bash(script_content):
            score += self.remote_mgmt_weight
            legitimate_indicators.append('Service management present')
            adjustments.append(f'{self.remote_mgmt_weight:+.0f} (service mgmt)')

        # Package management detection
        pkg_detected = False
        if language == 'powershell':
            pkg_detected = self.detect_package_management_powershell(script_content)
        elif language == 'bash':
            pkg_detected = self.detect_package_management_bash(script_content)
        elif language == 'javascript':
            pkg_detected = self.detect_package_management_javascript(script_content)

        if pkg_detected:
            score += self.package_mgmt_weight
            legitimate_indicators.append('Package management present')
            adjustments.append(f'{self.package_mgmt_weight:+.0f} (package mgmt)')

        # Build tools (Bash specific)
        if language == 'bash' and self.detect_build_tools_bash(script_content):
            score += self.build_tools_weight
            legitimate_indicators.append('Build/CI tools present')
            adjustments.append(f'{self.build_tools_weight:+.0f} (build tools)')

        # Testing framework detection
        testing_detected = False
        if language == 'bash':
            testing_detected = self.detect_testing_bash(script_content)
        elif language == 'javascript':
            testing_detected = self.detect_testing_javascript(script_content)

        if testing_detected:
            score += self.testing_weight
            legitimate_indicators.append('Testing framework present')
            adjustments.append(f'{self.testing_weight:+.0f} (testing)')

        # Framework detection (JavaScript specific)
        if language == 'javascript' and self.detect_framework_javascript(script_content):
            score += -10  # Frameworks are strong legitimacy indicators
            legitimate_indicators.append('Framework usage detected')
            adjustments.append('-10 (framework)')

        # =====================================================================
        # MALICIOUS INDICATORS (increase score)
        # =====================================================================

        if self.detect_hardcoded_credentials(script_content, language):
            score += self.hardcoded_creds_weight
            malicious_indicators.append('Hardcoded credentials detected')
            adjustments.append(f'+{self.hardcoded_creds_weight:.0f} (hardcoded creds)')

        if self.detect_download_execute(script_content, language):
            score += self.download_exec_weight
            malicious_indicators.append('Download + execute pattern')
            adjustments.append(f'+{self.download_exec_weight:.0f} (download+execute)')

        if self.detect_user_creation(script_content, language):
            score += self.user_creation_weight
            malicious_indicators.append('User creation detected')
            adjustments.append(f'+{self.user_creation_weight:.0f} (user creation)')

        if self.detect_security_cascade(script_content, language):
            score += self.security_cascade_weight
            malicious_indicators.append('Multiple security disables (cascade)')
            adjustments.append(f'+{self.security_cascade_weight:.0f} (security cascade)')

        if self.detect_obfuscation(script_content, language):
            score += self.obfuscation_weight
            malicious_indicators.append('Obfuscation detected')
            adjustments.append(f'+{self.obfuscation_weight:.0f} (obfuscation)')

        # =====================================================================
        # FINAL SCORE CALCULATION
        # =====================================================================

        # Clamp to valid range [0, 100]
        final_score = self.validate_score(score)

        # Build explanations
        total_adjustment = final_score - base_score
        explanations.append(
            f"Context-aware score: {final_score:.1f}/100 "
            f"(base: {base_score:.1f}, adjustment: {total_adjustment:+.1f}, lang: {language})"
        )

        if legitimate_indicators:
            explanations.append(f"Legitimate indicators ({len(legitimate_indicators)}): {', '.join(legitimate_indicators)}")

        if malicious_indicators:
            explanations.append(f"Malicious indicators ({len(malicious_indicators)}): {', '.join(malicious_indicators)}")

        if adjustments:
            explanations.append(f"Score adjustments: {', '.join(adjustments)}")

        if not legitimate_indicators and not malicious_indicators:
            explanations.append("No context indicators detected - score unchanged")

        return final_score, explanations
