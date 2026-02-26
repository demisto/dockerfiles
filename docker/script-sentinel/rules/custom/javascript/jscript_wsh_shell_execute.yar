/*
    YARA Rule: JScript WSH Shell Execution

    Detects JScript/WSH malware patterns using WScript.Shell
    for command execution and environment access.

    MITRE ATT&CK: T1059.007 (JavaScript), T1059.003 (Windows Command Shell)
*/

rule JScript_WScript_Shell_Run
{
    meta:
        description = "Detects JScript using WScript.Shell to run commands"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.007"
        category = "execution"

    strings:
        $wscript_shell = "WScript.Shell" nocase
        $createobject = "CreateObject" nocase
        $run = ".Run" nocase
        $expandenv = "ExpandEnvironmentStrings" nocase

    condition:
        $wscript_shell and $createobject and ($run or $expandenv)
}

rule JScript_WScript_Env_Temp_Drop
{
    meta:
        description = "Detects JScript dropping files to TEMP directory"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.9"
        mitre_technique = "T1059.007"
        category = "dropper"

    strings:
        $expandenv = "ExpandEnvironmentStrings" nocase
        $temp1 = "%TEMP%" nocase
        $temp2 = "%TMP%" nocase
        $temp3 = "GetSpecialFolder" nocase
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $bat = ".bat" nocase

    condition:
        $expandenv and
        ($temp1 or $temp2 or $temp3) and
        ($exe or $scr or $bat)
}

rule JScript_WScript_Hidden_Execution
{
    meta:
        description = "Detects JScript running processes in hidden mode"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1564.003"
        category = "defense_evasion"

    strings:
        $wscript_shell = "WScript.Shell" nocase
        $run = ".Run" nocase
        $hidden1 = /\.Run\s*\([^,]+,\s*0/
        $hidden2 = /\.Run\s*\([^,]+,\s*false/i

    condition:
        $wscript_shell and $run and ($hidden1 or $hidden2)
}
