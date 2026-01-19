rule rule_012_Malicious_Browser_History_Deletion {
    meta:
        description = "Browser history deletion for anti-forensics purposes"
        severity = "Medium"
        confidence = "0.91"
        mitre_technique = "T1070.003"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "08d4f440aac5d057"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $chrome = "Google\\Chrome\\User Data\\Default\\History" nocase
        $edge = "Microsoft\\Edge\\User Data\\Default\\History" nocase
        $firefox = "Mozilla\\Firefox\\Profiles*.default\\places.sqlite" nocase
        $sql1 = "System.Data.SQLite.SQLiteConnection" nocase
        $sql2 = "DELETE FROM urls" nocase
        $sql3 = "ExecuteNonQuery" nocase

    condition:
        2 of ($chrome, $edge, $firefox) and all of ($sql*)
}