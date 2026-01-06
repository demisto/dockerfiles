rule rule_043_Suspicious_PowerShell_Executable_Download_Pattern {
    meta:
        description = "PowerShell downloading executable to temp directory and executing"
        severity = "High"
        confidence = "0.90"
        mitre_technique = "T1105"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "49e134e5a05a6449,4c84983be37209b0,4d4c3e1b44e7ea3d,4de59496812770d5,4fa63163f3008d7f"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Download to temp locations
        $temp_download1 = "DownloadFile(" nocase
        $temp_path1 = "$env:APPDATA\\" nocase
        $temp_path2 = "$env:TEMP\\" nocase
        
        // Executable file extension
        $exe_ext = ".exe" nocase
        
        // Immediate execution
        $execute1 = "Start-Process (" nocase
        $execute2 = "& " nocase
        
        // Suspicious filename patterns
        $suspicious_name = /[a-z]{4,8}\.exe/ nocase

    condition:
        $temp_download1 and 
        any of ($temp_path*) and 
        $exe_ext and 
        any of ($execute*) and
        $suspicious_name
}