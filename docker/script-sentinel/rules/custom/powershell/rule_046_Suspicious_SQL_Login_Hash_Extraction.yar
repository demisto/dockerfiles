rule rule_046_Suspicious_SQL_Login_Hash_Extraction {
    meta:
        description = "SQL Server password hash extraction for credential dumping"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1003.003"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "526007963ef9c193"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // SQL queries targeting password hashes
        $hash_query1 = "password_hash" nocase
        $hash_query2 = "sys.sql_logins" nocase
        $hash_query3 = "convert(varbinary" nocase
        
        // Hash manipulation functions
        $hash_func1 = "Convert-SQLHashToString" nocase
        $hash_func2 = "PASSWORD = $passtring hashed" nocase
        
        // Login manipulation
        $login_script = "LoginSid = $true" nocase
        $login_copy = "Copy-SqlLogins" nocase
        
        // SMO objects for SQL manipulation
        $smo = "Microsoft.SqlServer.Management.Smo" nocase

    condition:
        (any of ($hash_query*) and any of ($hash_func*)) or
        ($login_copy and $login_script and $smo)
}