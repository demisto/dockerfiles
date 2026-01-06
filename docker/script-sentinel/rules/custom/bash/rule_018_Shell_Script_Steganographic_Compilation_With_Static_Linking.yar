rule rule_018_Shell_Script_Steganographic_Compilation_With_Static_Linking {
    meta:
        description = "Shell script performing static compilation with suspicious patterns"
        severity = "Medium"
        confidence = "0.73"
        mitre_technique = "T1027.002"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "8b4ca03d65b9be83,b57f72b77a5cc34a"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Compiler invocations
        $gcc1 = "gcc" nocase
        $gcc2 = "${PREFIX}gcc" nocase
        $gcc3 = "cc " nocase
        
        // Static linking and optimization flags
        $static1 = "-static" nocase
        $static2 = "STATIC=" nocase
        $opt1 = "-Os" nocase
        $opt2 = "-O2" nocase
        $opt3 = "-O3" nocase
        
        // Suspicious compilation patterns
        $flags1 = "-Wall" nocase
        $flags2 = "-I.." nocase
        $flags3 = ".a " nocase
        $flags4 = "libmatrixssl" nocase
        
        // Version or string manipulation
        $manip1 = "tr -d" nocase
        $manip2 = "sed " nocase
        $manip3 = "grep " nocase
        $manip4 = "%%"

    condition:
        any of ($gcc*) and any of ($static*) and any of ($opt*) and 
        (any of ($flags*) or any of ($manip*))
}