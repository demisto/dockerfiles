/*
    YARA Rule: JScript Download and Save Patterns

    Detects JScript malware with download and file save operations
    that may not have explicit shell execution.

    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
*/

rule JScript_XMLHTTP_ResponseBody_Save
{
    meta:
        description = "Detects JScript downloading via XMLHTTP and saving responseBody"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $xmlhttp1 = "XMLHTTP" nocase
        $xmlhttp2 = "MSXML" nocase
        $responsebody = "responseBody" nocase
        $savetofile = "saveToFile" nocase
        $write = ".Write" nocase
        $type1 = ".Type" nocase

        // File paths/extensions
        $temp = "%TEMP%" nocase
        $appdata = "%APPDATA%" nocase
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $dll = ".dll" nocase

    condition:
        ($xmlhttp1 or $xmlhttp2) and $responsebody and
        ($savetofile or $write or $type1) and
        ($temp or $appdata or $exe or $scr or $dll)
}

rule JScript_ADODB_Stream_Binary
{
    meta:
        description = "Detects JScript using ADODB.Stream in binary mode"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $adodb = "ADODB.Stream" nocase
        $type_binary = /\.Type\s*=\s*1/
        $mode_write = /\.Mode\s*=\s*3/
        $open = ".Open" nocase
        $write = ".Write" nocase
        $savetofile = "SaveToFile" nocase
        $position = ".Position" nocase

    condition:
        $adodb and ($type_binary or $mode_write) and
        ($open or $write or $savetofile or $position)
}

rule JScript_ExpandEnv_File_Drop
{
    meta:
        description = "Detects JScript using ExpandEnvironmentStrings to drop files"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $expand = "ExpandEnvironmentStrings" nocase
        $temp = "%TEMP%" nocase
        $appdata = "%APPDATA%" nocase
        $localappdata = "%LOCALAPPDATA%" nocase
        $userprofile = "%USERPROFILE%" nocase

        // File operations
        $savetofile = "saveToFile" nocase
        $write = ".Write" nocase
        $createtext = "CreateTextFile" nocase
        $copy = "CopyFile" nocase

        // Extensions
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $dll = ".dll" nocase
        $bat = ".bat" nocase
        $vbs = ".vbs" nocase

    condition:
        $expand and
        ($temp or $appdata or $localappdata or $userprofile) and
        ($savetofile or $write or $createtext or $copy) and
        ($exe or $scr or $dll or $bat or $vbs)
}

rule JScript_HTTP_URL_Download
{
    meta:
        description = "Detects JScript with HTTP URL and download indicators"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1105"
        category = "network"

    strings:
        $http = "http://" nocase
        $https = "https://" nocase

        // Download methods
        $open = ".open" nocase
        $send = ".send" nocase

        // Response handling
        $responsebody = "responseBody" nocase
        $responsetext = "responseText" nocase

        // Object creation
        $createobj = "CreateObject" nocase
        $activex = "ActiveXObject" nocase

    condition:
        ($http or $https) and
        ($open and $send) and
        ($responsebody or $responsetext) and
        ($createobj or $activex)
}

rule JScript_CC_On_Download
{
    meta:
        description = "Detects JScript with @cc_on and download patterns"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $cc_on = "@cc_on"
        $win32 = "@_win32" nocase
        $win64 = "@_win64" nocase

        // Download indicators
        $xmlhttp = "XMLHTTP" nocase
        $responsebody = "responseBody" nocase
        $adodb = "ADODB" nocase
        $savetofile = "saveToFile" nocase

        // Extensions
        $exe = ".exe" nocase
        $scr = ".scr" nocase

    condition:
        $cc_on and ($win32 or $win64) and
        (
            ($xmlhttp and $responsebody) or
            ($adodb and $savetofile)
        ) and
        ($exe or $scr)
}

