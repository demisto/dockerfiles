rule rule_022_Malicious_JS_Remote_Injection_Via_Shell_Script {
    meta:
        description = "Shell script downloading and injecting remote JavaScript into local files"
        severity = "Critical"
        confidence = "0.92"
        mitre_technique = "T1105"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "957760379ce493d3"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Remote URL patterns for JS content
        $remote_js = /REMOTE_URL=.*\.js"/ nocase
        
        // JavaScript obfuscation patterns
        $js_obfus1 = "_0x" nocase
        $js_obfus2 = "TARGET_STRING" nocase
        
        // File modification patterns
        $find_js = "find . -type f -name \"*.js\"" nocase
        $append_file = "cat \"$TEMP_FILE\" >> \"$f\"" nocase
        
        // Download methods
        $download1 = "wget -q" nocase
        $download2 = "curl -s" nocase
        
        // Self-deletion behavior
        $self_delete = "rm -f \"$SCRIPT_NAME\"" nocase
        
        // Grep for existing injection
        $check_inject = "grep -qF \"$TARGET_STRING\"" nocase

    condition:
        $remote_js and 
        any of ($js_obfus*) and 
        $find_js and 
        $append_file and 
        any of ($download*) and
        $self_delete and
        $check_inject
}