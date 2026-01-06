rule rule_004_Malicious_Bash_Ransomware_Decryption_Script {
    /*
     * Detects ransomware decryption scripts that decrypt files using
     * RSA private keys and clean up ransom instruction files.
     * Common in ransomware recovery tools and decryptors.
     */
    meta:
        description = "Ransomware decryption script with RSA key and file mapping cleanup"
        severity = "High"
        confidence = "0.92"
        mitre_technique = "T1486"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "3e8e324c0b113280"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // RSA private key manipulation
        $rsa1 = "BEGIN RSA PRIVATE KEY" nocase
        $rsa2 = "openssl rsautl -decrypt" nocase
        $rsa3 = "/root/priv.pem" nocase
        
        // File mapping and batch decryption
        $decrypt1 = "file_mapping.db" nocase
        $decrypt2 = "openssl enc -aes-256-cbc -d" nocase
        $decrypt3 = "-pass file:" nocase
        
        // Ransom note cleanup
        $cleanup1 = "INSTRUCTIONS.txt" nocase
        $cleanup2 = "INSTRUCTIONS.html" nocase
        
        // Batch processing pattern
        $batch = "for file in $(" nocase

    condition:
        any of ($rsa*) and any of ($decrypt*) and any of ($cleanup*) and $batch
}