rule rule_011_Suspicious_Data_Exfiltration_Functions {
    meta:
        description = "Data exfiltration functions for file splitting and upload"
        severity = "High"
        confidence = "0.87"
        mitre_technique = "T1041"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "00c0479f83c3dbbe"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $func1 = "Invoke-PostExfil" nocase
        $func2 = "function split" nocase
        $split1 = "System.IO.File]::OpenRead" nocase
        $split2 = "System.IO.File]::OpenWrite" nocase
        $chunk1 = "chunkNum" nocase
        $chunk2 = "bufSize" nocase
        $exfil1 = "exfil" nocase
        $server1 = "Server" nocase

    condition:
        any of ($func*) and 2 of ($split*) and any of ($chunk*) and ($exfil1 or $server1)
}