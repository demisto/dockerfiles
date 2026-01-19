rule rule_042_Malicious_PowerShell_Appended_Payload {
    meta:
        description = "PowerShell script with malicious payload appended to legitimate code"
        severity = "High"
        confidence = "0.92"
        mitre_technique = "T1027.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "49e134e5a05a6449,4c84983be37209b0,4d4c3e1b44e7ea3d,4de59496812770d5,4fa63163f3008d7f"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Legitimate PowerShell function patterns
        $legit1 = "function " nocase
        $legit2 = "[CmdletBinding()]" nocase
        $legit3 = "param(" nocase
        
        // Malicious payload patterns typically at end
        $payload1 = "(New-Object System.Net.WebClient).DownloadFile(" nocase
        $payload2 = ");Start-Process (" nocase
        
        // Suspicious domains/IPs
        $suspicious_url = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ nocase
        $suspicious_path = /~\w+\/\w+\.exe/ nocase

    condition:
        any of ($legit*) and 
        any of ($payload*) and 
        (any of ($suspicious_url) or any of ($suspicious_path)) and
        filesize > 5KB
}