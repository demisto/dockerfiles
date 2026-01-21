rule rule_025_Suspicious_Shell_Binary_Data_Reconstruction {
    meta:
        description = "Shell script reconstructing binary data from hex representation"
        severity = "Medium"
        confidence = "0.78"
        mitre_technique = "T1027"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "9c679e66e00ee912"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Hex pattern matching for binary reconstruction
        $hex_pattern1 = /\[0-9a-f\]\[0-9a-f\]/ nocase
        $hex_pattern2 = "hexdump -R" nocase
        $hex_pattern3 = "od -tx1" nocase
        
        // Binary reconstruction indicators
        $reconstruct1 = "grep -a" nocase
        $reconstruct2 = /\^[0-7]\[0-7\]\[0-7\]/ nocase
        
        // Shell indicators
        $shell1 = "#!/bin/sh" nocase
        $shell2 = "#!/bin/bash" nocase
    
    condition:
        any of ($shell*) and 
        any of ($hex_pattern*) and 
        any of ($reconstruct*)
}