rule rule_020_Suspicious_Speech_Synthesis_Troll {
    meta:
        description = "PowerShell speech synthesis function for potential harassment or trolling"
        severity = "Low"
        confidence = "0.78"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "02c0858f446ac918"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        $func1 = "Invoke-VoiceTroll" nocase
        $func2 = "Function Invoke-VoiceTroll" nocase
        $speech1 = "System.Speech" nocase
        $speech2 = "SpeechSynthesizer" nocase
        $speak1 = "Speak(" nocase
        $param1 = "VoiceText" nocase

    condition:
        any of ($func*) and any of ($speech*) and $speak1 and $param1
}