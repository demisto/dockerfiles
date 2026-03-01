rule rule_023_Suspicious_Shell_Success_IPs_Webshell_Testing {
    meta:
        description = "Script testing for webshells across multiple IPs from success list"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1505.003"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "8bb1004511631650"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Reading from success IPs file
        $success_file = "success_ips.txt" nocase
        
        // Webshell testing patterns
        $shell_jsp = "shell.jsp" nocase
        $webshell_test1 = "NextJS Upload Test" nocase
        $webshell_test2 = "<%@" nocase
        $webshell_test3 = "java.io" nocase
        
        // Command execution testing
        $cmd_test = "shell.jsp?cmd=" nocase
        $cmd_id = "?cmd=id" nocase
        
        // Status messages
        $shell_exists = "Shell存在" nocase
        $shell_missing = "Shell不存在" nocase
        $cmd_exec_test = "执行命令测试" nocase
        
        // IP/URL extraction
        $awk_extract = "awk -F'|'" nocase

    condition:
        $success_file and 
        $shell_jsp and 
        any of ($webshell_test*) and 
        any of ($cmd_test, $cmd_id) and 
        $awk_extract and
        any of ($shell_exists, $shell_missing, $cmd_exec_test)
}