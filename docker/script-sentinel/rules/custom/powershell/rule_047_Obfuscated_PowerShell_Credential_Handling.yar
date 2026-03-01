rule rule_047_Obfuscated_PowerShell_Credential_Handling {
    meta:
        description = "Suspicious PowerShell credential handling and manipulation patterns"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1555"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "154c8b6cb5173c8d,28bb7e1ba0e9c7e5"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Credential creation patterns
        $cred1 = "ConvertTo-SecureString" nocase
        $cred2 = "AsPlainText -Force" nocase
        $cred3 = "System.Management.Automation.PSCredential" nocase
        $cred4 = "New-Object System.Net.NetworkCredential" nocase
        
        // Suspicious credential functions
        $func1 = "New-TestCredentials" nocase
        $func2 = "Verify-CredentialsInServer" nocase
        $func3 = "New-RsRestCredentialsInServerObject" nocase
        
        // SMTP credential handling (often used in data exfiltration)
        $smtp1 = "SMTPClient.Credentials" nocase
        $smtp2 = "System.Net.Mail.SmtpClient" nocase
        
        // Password handling
        $pass1 = "dummyPassword" nocase
        $pass2 = ".Password =" nocase

    condition:
        (($cred1 and $cred2 and $cred3) or $cred4) and
        (any of ($func*) or any of ($smtp*) or any of ($pass*))
}