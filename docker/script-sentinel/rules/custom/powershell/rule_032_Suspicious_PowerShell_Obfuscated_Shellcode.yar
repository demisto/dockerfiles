rule rule_032_Suspicious_PowerShell_Obfuscated_Shellcode {
    meta:
        description = "Detects obfuscated PowerShell with shellcode and memory manipulation"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1055"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "32bcff55ccf0d8c3"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Obfuscation patterns
        $obfusc1 = /\$[a-zA-Z]+\s*=\s*[0-9]+~[0-9]+/ nocase
        $obfusc2 = /[0-9]+[~%>LhwsFU,]+[0-9]+/ nocase
        
        // Memory manipulation APIs
        $api1 = "VirtualAlloc" nocase
        $api2 = "CreateThread" nocase
        $api3 = "memset" nocase
        $api4 = "DllImport" nocase
        
        // Kernel32 references
        $kernel32 = "kernel32.dll" nocase
        
        // Hex patterns typical of shellcode
        $hex_pattern = /0x[a-fA-F0-9]{2}/ nocase

    condition:
        2 of ($obfusc*) and 2 of ($api*) and $kernel32 and #hex_pattern > 50
}