rule rule_029_Malicious_PowerShell_Persistence_Mechanism {
    meta:
        description = "PowerShell establishing persistence via startup folder manipulation"
        severity = "High"
        confidence = "0.87"
        mitre_technique = "T1547.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "2c3dba9a5803c2a2"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Startup folder access
        $startup1 = "GetFolderPath('Startup')" nocase
        $startup2 = "[Environment]::GetFolderPath('Startup')" nocase
        
        // Shortcut creation
        $shortcut1 = "CreateShortcut" nocase
        $shortcut2 = "WScript.Shell" nocase
        $shortcut3 = ".lnk" nocase
        
        // File system manipulation
        $file1 = "TargetPath" nocase
        $file2 = ".Save()" nocase
        
        // Multiple downloads
        $download1 = "iwr " nocase
        $download2 = "-OutFile" nocase

    condition:
        any of ($startup*) and any of ($shortcut*) and 
        ($file1 or $file2) and any of ($download*)
}