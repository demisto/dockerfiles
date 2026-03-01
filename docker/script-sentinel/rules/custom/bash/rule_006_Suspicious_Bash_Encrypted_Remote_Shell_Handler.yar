rule rule_006_Suspicious_Bash_Encrypted_Remote_Shell_Handler {
    /*
     * Detects bash scripts that implement encrypted command handlers
     * with base64 encoding and shell execution capabilities, often
     * used in covert communication channels.
     */
    meta:
        description = "Encrypted shell command handler with base64 encoding and remote execution"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1027"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "30f07f2f8bb25d9a"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Encryption/encoding functions
        $crypt1 = "enc -d -a" nocase
        $crypt2 = "enc -a" nocase
        $crypt3 = "-iv $IV -K $PRIVKEY" nocase
        
        // Shell execution with logging
        $exec1 = "$SHELL -c" nocase
        $exec2 = "tee -a $LOG" nocase
        
        // Function definitions for encode/decode
        $func1 = "decode() {" nocase
        $func2 = "encode() {" nocase
        $func3 = "run() {" nocase
        
        // OpenSSL usage
        $ssl = "$OPENSSL" nocase

    condition:
        any of ($crypt*) and any of ($exec*) and 2 of ($func*) and $ssl
}