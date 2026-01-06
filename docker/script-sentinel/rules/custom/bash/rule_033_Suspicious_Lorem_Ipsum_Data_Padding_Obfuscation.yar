rule rule_033_Suspicious_Lorem_Ipsum_Data_Padding_Obfuscation {
    /*
     * Detects repetitive Lorem Ipsum text patterns that may be used
     * for data padding, obfuscation, or hiding malicious content.
     */
    meta:
        description = "Repetitive Lorem Ipsum text used for potential obfuscation"
        severity = "Medium"
        confidence = "0.82"
        mitre_technique = "T1027.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "dc91725cc85d03f5"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Lorem Ipsum patterns
        $lorem1 = "Lorem ipsum dolor sit amet," nocase
        $lorem2 = "Duis bibendum lectus nec nis" nocase
        $lorem3 = "Phasellus efficitur massa eg" nocase
        $lorem4 = "Nullam nec imperdiet odio. P" nocase
        $lorem5 = "Aliquam felis dui, volutpat" nocase
        
        // Repetition indicators
        $repeat_pattern = /Lorem ipsum dolor sit amet,.*Lorem ipsum dolor sit amet,/s nocase

    condition:
        // High repetition of Lorem Ipsum fragments (5+ occurrences)
        (#lorem1 >= 5 and #lorem2 >= 5) or 
        (#lorem1 >= 3 and $repeat_pattern and any of ($lorem2, $lorem3, $lorem4, $lorem5))
}