rule rule_005_Suspicious_PowerShell_TCP_Socket_Communication {
    meta:
        description = "PowerShell TCP socket creation for potential reverse shell or backdoor"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "0224adf38031d6d6"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $socket1 = "System.Net.Sockets.TcpListener" nocase
        $socket2 = "System.Net.Sockets.TcpClient" nocase
        $socket3 = "AcceptTcpClient" nocase
        $stream1 = "GetStream" nocase
        $stream2 = "StreamWriter" nocase
        $read1 = "Read-Host" nocase
        $read2 = "stream.Read" nocase

    condition:
        any of ($socket*) and any of ($stream*) and any of ($read*)
}