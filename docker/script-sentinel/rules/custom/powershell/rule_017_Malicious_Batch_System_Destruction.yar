rule rule_017_Malicious_Batch_System_Destruction {
    meta:
        description = "Batch script with destructive file deletion and system manipulation"
        severity = "Critical"
        confidence = "0.93"
        mitre_technique = "T1485"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "0f3c7c254132044d"
    approved_by = "Adi Peretz"
    approved_at = "2025-12-27"
    strings:
        $del1 = "del /f /s /q" nocase
        $del2 = "deltree" nocase
        $reg1 = "reg add" nocase
        $reg2 = "hkey_local_machine" nocase
        $files1 = "*.pdf" nocase
        $files2 = "*.docx" nocase
        $files3 = "*.jpg" nocase
        $msg1 = "Has Sido Hackeado" nocase
        $msg2 = "Virus Detectado" nocase
        $loop1 = "start \"\" %0" nocase

    condition:
        any of ($del*) and any of ($reg*) and 2 of ($files*) and (any of ($msg*) or $loop1)
}