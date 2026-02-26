rule rule_015_Suspicious_Server_Netcat_Command_Execution {
    meta:
        description = "Detects netcat-based server with command execution and persistence mechanisms"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.004"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "695b23c792c2e05d"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Netcat server setup
        $nc_listen = "$NC -nl" nocase
        $nc_execute = "-e " nocase
        $port_var = "-p $PORT" nocase
        $host_var = "$HOST:" nocase
        
        // Persistence and loop mechanisms
        $continue_loop = "while $CONTINUE" nocase
        $trap_exit = "trap" nocase
        $on_interrupt = "on_interrupt" nocase
        
        // Server management
        $manage_request = "manage-server-request" nocase
        $server_halted = "Server halted" nocase
        $start_server = "Start server" nocase

    condition:
        $nc_listen and $nc_execute and
        ($port_var or $host_var) and
        $continue_loop and
        ($trap_exit or $on_interrupt) and
        ($manage_request or ($server_halted and $start_server))
}