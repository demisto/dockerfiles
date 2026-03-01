rule rule_015_Malicious_Service_Masquerading_Persistence_Linux {
    meta:
        description = "Detects malware creating systemd services with deceptive names for persistence"
        severity = "High"
        confidence = "0.78"
        mitre_technique = "T1543.002"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "c7a0d6ccf56b187e"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Systemd service creation
        $systemd1 = "/etc/systemd/system/" nocase
        $systemd2 = "systemctl daemon-reload" nocase
        $systemd3 = "systemctl enable" nocase
        $systemd4 = "systemctl start" nocase
        
        // Masquerading service names
        $masq1 = "system-update" nocase
        $masq2 = "security-service" nocase
        $masq3 = "network-manager" nocase
        $masq4 = "system-monitor" nocase
        $masq5 = "kernel-update" nocase
        
        // Service file structure
        $service1 = "[Unit]" nocase
        $service2 = "[Service]" nocase
        $service3 = "[Install]" nocase
        $service4 = "ExecStart=" nocase
        $service5 = "WantedBy=multi-user.target" nocase
        
        // Suspicious execution paths
        $path1 = "ExecStart=/tmp/" nocase
        $path2 = "ExecStart=/var/tmp/" nocase
        $path3 = "ExecStart=$(pwd)" nocase
        $path4 = /ExecStart=.*\/home\/[^\/]+\// nocase

    condition:
        3 of ($systemd*) and 
        any of ($masq*) and 
        3 of ($service*) and
        any of ($path*)
}