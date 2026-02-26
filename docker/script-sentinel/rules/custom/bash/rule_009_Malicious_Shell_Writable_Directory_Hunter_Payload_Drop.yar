rule rule_009_Malicious_Shell_Writable_Directory_Hunter_Payload_Drop {
    meta:
        description = "Shell script systematically hunting for writable directories to deploy payloads"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1083"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "9c3e370c5d1a9732,b33d468641a0d3c8"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Directory enumeration patterns
        $find1 = "find" nocase
        $writable1 = "-writable" nocase
        $writable2 = "-perm -o+w" nocase
        $writable3 = "-user" nocase
        
        // System directory targets
        $dirs1 = "/home /root /opt /usr /var /etc" nocase
        $dirs2 = "/tmp /var/tmp" nocase
        
        // Permission testing
        $touch_test = "touch $i/test" nocase
        $touch_test2 = "! touch" nocase
        
        // Payload operations after finding writable location
        $download_to_dir = "-o \"$i/" nocase
        $chmod_in_dir = "chmod +x \"$i/" nocase
        
        // Loop constructs for directory iteration
        $for_dir = "for dir in" nocase
        $for_i = "for i in" nocase

    condition:
        $find1 and (any of ($writable*)) and 
        (any of ($dirs*)) and (any of ($touch_test*)) and
        (any of ($for_dir, $for_i)) and
        ($download_to_dir or $chmod_in_dir)
}