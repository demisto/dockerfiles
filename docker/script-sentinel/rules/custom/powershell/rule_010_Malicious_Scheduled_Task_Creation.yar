rule rule_010_Malicious_Scheduled_Task_Creation {
    meta:
        description = "Suspicious scheduled task creation for persistence"
        severity = "High"
        confidence = "0.88"
        mitre_technique = "T1053.005"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "21ab16b4881c4620,6a34d2d403504480,dbbe38017877a0b7"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $task1 = "new-object -ComObject" nocase
        $task2 = "Schedule.Service" nocase
        $task3 = ".Settings.Hidden = $true" nocase
        $task4 = "RegisterTaskDefinition" nocase
        $task5 = "SCHTASKS /run /TN" nocase
        $name = /"Microsoft.*Driver.*Update"/ nocase
    
    condition:
        3 of ($task*) or ($task1 and $task2 and $name)
}