rule rule_003_Malicious_PowerShell_Reflective_Assembly_Load {
    meta:
        description = "PowerShell reflective assembly loading from downloaded data"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1055.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "1d931998194a4ad6"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download data methods
        $download1 = "DownloadData(" nocase
        $download2 = "New-Object System.Net.WebClient" nocase
        
        // Reflective loading
        $reflect1 = "System.Reflection.Assembly" nocase
        $reflect2 = "Assembly]::Load(" nocase
        
        // Main execution
        $exec1 = "::Main(" nocase
        
        // Suspicious patterns
        $var1 = "$data" nocase
        $var2 = "$assem" nocase

    condition:
        any of ($download*) and any of ($reflect*) and $exec1 and (any of ($var*) or 2 of them)
}