rule rule_027_Malicious_PowerShell_Obfuscated_Download_Chain {
    meta:
        description = "Obfuscated PowerShell with variable-based download and execution chain"
        severity = "High"
        confidence = "0.89"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2c3dba9a5803c2a2,2e1b008e1b149ade"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Obfuscated variable patterns
        $var1 = /\$[a-z]=[^;]{10,}/ nocase
        $var2 = /\$[a-z]{1,3}=\$env:/ nocase
        
        // Web request methods
        $web1 = "iwr " nocase
        $web2 = "Invoke-WebRequest" nocase
        $web3 = "DownloadFile" nocase
        
        // Multiple file operations in sequence
        $file1 = "-OutFile" nocase
        
        // Startup folder manipulation
        $startup1 = "GetFolderPath('Startup')" nocase
        $startup2 = "CreateShortcut" nocase
        
        // Execution bypass
        $bypass1 = "-exec bypass" nocase

    condition:
        (any of ($var*) and any of ($web*) and $file1) or 
        (any of ($startup*) and any of ($web*)) or 
        ($bypass1 and any of ($web*))
}