/*
    YARA Rule: JScript Conditional Compilation Dropper

    Detects JScript malware using @cc_on conditional compilation
    directive, commonly used in WSH-based droppers.

    MITRE ATT&CK: T1059.007 (JavaScript)
*/

rule JScript_CC_On_Windows_Check
{
    meta:
        description = "Detects JScript using @cc_on for Windows version detection"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.8"
        mitre_technique = "T1059.007"
        category = "execution"

    strings:
        $cc_on = "/*@cc_on"
        $win32 = "@_win32" nocase
        $win64 = "@_win64" nocase
        $end = "@end"
        $createobject = "CreateObject" nocase

    condition:
        $cc_on and ($win32 or $win64) and $end and $createobject
}

rule JScript_CC_On_Download_Execute
{
    meta:
        description = "Detects JScript dropper with @cc_on and download/execute pattern"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.9"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $cc_on = "/*@cc_on"
        $xmlhttp = /MSXML2?\.XMLHTTP/i
        $adodb = "ADODB.Stream" nocase
        $shell = "WScript.Shell" nocase
        $run = ".Run" nocase
        $responsebody = "responseBody" nocase

    condition:
        $cc_on and
        ($xmlhttp or $adodb) and
        ($shell or $run) and
        $responsebody
}
