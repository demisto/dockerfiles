rule rule_002_Malicious_Telegram_Bot_C2_With_Password_Decryption {
    /*
     * Detects malware using Telegram bot API for C2 communication
     * combined with OpenSSL password decryption capabilities.
     *
     * Example match:
     *   TOKEN='1322235264:AAE7QI-f1GtAF_huVz8E5IBdb5JbWIIiGKI'
     *   URL='https://api.telegram.org/bot'$TOKEN
     *   PASS_DEC=$(openssl enc -base64 -aes-256-cbc -d -pass pass:$PASS_DE <<< $1)
     */
    meta:
        description = "Malware using Telegram bot C2 with OpenSSL password decryption"
        severity = "Critical"
        confidence = "0.89"
        mitre_technique = "T1071.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "1c2b09417c1a34bb"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Telegram bot API patterns
        $tg1 = "api.telegram.org/bot" nocase
        $tg2 = "sendMessage" nocase
        $tg3 = "chat_id=" nocase
        
        // Bot token pattern (Telegram bot tokens have specific format)
        $token = /[0-9]{8,10}:[A-Za-z0-9_-]{35}/ nocase
        
        // OpenSSL decryption
        $ssl1 = "openssl enc" nocase
        $ssl2 = "-aes-256-cbc" nocase
        $ssl3 = "-base64" nocase
        $ssl4 = "-d -pass pass:" nocase
        
        // C2 communication indicators
        $c2_1 = "apirequests=" nocase
        $c2_2 = "curl -s" nocase
        
        // Malicious actions
        $action1 = "passwd $n" nocase
        $action2 = "usermod --shell /bin/nologin" nocase
        $action3 = "pkill -9 -t" nocase

    condition:
        2 of ($tg*) and 
        ($token or (2 of ($ssl*))) and 
        any of ($c2_*) and 
        any of ($action*)
}