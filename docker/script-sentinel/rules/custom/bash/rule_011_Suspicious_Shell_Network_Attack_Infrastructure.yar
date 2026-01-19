rule rule_011_Suspicious_Shell_Network_Attack_Infrastructure {
    meta:
        description = "Detects shell scripts implementing network attack infrastructure with process management"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "6b3170a83fb7a8a8"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Network utilities commonly used in attacks
        $net1 = "$NC" nocase
        $net2 = "netcat" nocase
        $net3 = "-nl" nocase
        $net4 = "-p $PORT" nocase

        // Process/status management for attacks
        $proc1 = "/tmp/.status" nocase
        $proc2 = "statfile" nocase
        $proc3 = "kill -9" nocase
        $proc4 = "echo \"$!\"" nocase

        // Attack execution indicators
        $exec1 = ">/dev/null &" nocase
        $exec2 = "System is busy" nocase
        $exec3 = "killIt" nocase

        // Suspicious variable patterns
        $var1 = "$ip $port $threads $secs" nocase
        $var2 = "thisbot" nocase
        $var3 = "$HOST:$PORT" nocase

    condition:
        (any of ($net*) and any of ($proc*) and any of ($exec*)) or
        (any of ($var*) and any of ($proc*))
}