rule rule_023_Malicious_DLL_Sideloading_Setup {
    meta:
        description = "DLL sideloading attack preparation"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1574.002"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "b845f47a92cf8a6d,c3d42a5ff6212be9"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $path1 = "\\\\?\\C:\\Windows " nocase
        $path2 = "C:\\Windows \\System32" nocase
        $copy = "Copy-Item" nocase
        $regsvr = "regsvr32" nocase
        $dll = ".dll" nocase
        $space_dir = /New-Item.*"[^"]*\s+".*Directory/i
    
    condition:
        ($path1 or $path2 or $space_dir) and ($copy or $regsvr) and $dll
}