rule rule_016_Suspicious_VBS_Download_Execute {
    meta:
        description = "PowerShell downloading and executing VBS files via wscript"
        severity = "High"
        confidence = "0.89"
        mitre_technique = "T1059.005"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "198c687b176c90c4"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $download1 = "Invoke-WebRequest" nocase
        $download2 = "-OutFile" nocase
        $vbs1 = ".vbs" nocase
        $exec1 = "wscript.exe" nocase
        $exec2 = "Start-Process" nocase
        $temp1 = "$env:TEMP" nocase
        $random1 = "Get-Random" nocase

    condition:
        all of ($download*) and $vbs1 and all of ($exec*) and ($temp1 or $random1)
}