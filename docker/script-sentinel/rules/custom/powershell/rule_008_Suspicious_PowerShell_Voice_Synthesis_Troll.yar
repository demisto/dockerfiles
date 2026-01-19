rule rule_008_Suspicious_PowerShell_Voice_Synthesis_Troll {
    meta:
        description = "PowerShell voice synthesis with suspicious troll functionality"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1106"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-27"
    source_scripts = "02c0858f446ac918"
    approved_by = "Amelia (Dev Agent)"
    approved_at = "2025-12-27"
    strings:
        // Voice synthesis components
        $voice1 = "System.Speech.Synthesis" nocase
        $voice2 = "SpeechSynthesizer" nocase
        $voice3 = ".Speak(" nocase
        
        // Troll-related naming
        $troll1 = "VoiceTroll" nocase
        $troll2 = "Invoke-VoiceTroll" nocase
        
        // Assembly loading
        $assembly = "Add-Type -AssemblyName System.Speech" nocase

    condition:
        any of ($voice*) and any of ($troll*) and ($assembly or 2 of ($voice*))
}