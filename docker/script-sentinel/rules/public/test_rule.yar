rule test_invoke_expression {
    meta:
        description = "Detects PowerShell Invoke-Expression"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.001"
    strings:
        $s1 = "Invoke-Expression" nocase
        $s2 = "IEX" nocase
    condition:
        any of them
}
