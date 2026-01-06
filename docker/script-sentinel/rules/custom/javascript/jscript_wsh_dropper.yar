/*
    YARA Rule: JScript WSH Dropper Patterns

    Detects various JScript/WSH dropper techniques including
    environment access, file creation, and payload execution.

    MITRE ATT&CK: T1059.007 (JavaScript), T1105 (Ingress Tool Transfer)
*/

rule JScript_WSH_Complete_Dropper
{
    meta:
        description = "Detects complete JScript WSH dropper chain"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        // Network component
        $xmlhttp = "XMLHTTP" nocase
        $responsebody = "responseBody" nocase

        // Stream component
        $adodb = "ADODB.Stream" nocase
        $savetofile = "saveToFile" nocase

        // Path component
        $expand = "ExpandEnvironmentStrings" nocase
        $temp = "%TEMP%" nocase

        // Extension
        $scr = ".scr" nocase
        $exe = ".exe" nocase

    condition:
        $xmlhttp and $responsebody and $adodb and $savetofile and
        ($expand or $temp) and ($scr or $exe)
}

rule JScript_CreateObject_Chain
{
    meta:
        description = "Detects JScript with multiple CreateObject calls forming dropper chain"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.007"
        category = "execution"

    strings:
        $createobj = "CreateObject" nocase

        // Multiple object types
        $xmlhttp = "XMLHTTP" nocase
        $adodb = "ADODB" nocase
        $shell = "Shell" nocase
        $fso = "FileSystemObject" nocase

    condition:
        #createobj >= 2 and
        ($xmlhttp and ($adodb or $fso)) or
        ($adodb and $shell) or
        ($xmlhttp and $shell)
}

rule JScript_WSH_Implicit_Dropper
{
    meta:
        description = "Detects JScript dropper with implicit patterns"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        // HTTP request indicators
        $open_method = ".open" nocase
        $send_method = ".send" nocase
        $status = ".status" nocase

        // Response handling
        $responsebody = "responseBody" nocase
        $responsetext = "responseText" nocase

        // Binary save
        $type1 = /\.Type\s*=\s*1/
        $write = ".Write" nocase

    condition:
        ($open_method and $send_method) and
        ($responsebody or $responsetext) and
        ($type1 or $write or $status)
}

rule JScript_SCR_Dropper
{
    meta:
        description = "Detects JScript specifically dropping .scr screensaver files"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Critical"
        confidence = "0.90"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $scr = ".scr" nocase
        $adodb = "ADODB" nocase
        $stream = "Stream" nocase
        $xmlhttp = "XMLHTTP" nocase
        $responsebody = "responseBody" nocase
        $savetofile = "saveToFile" nocase
        $write = ".Write" nocase
        $type1 = /\.Type\s*=\s*1/

    condition:
        $scr and ($adodb or $stream) and
        ($xmlhttp or $responsebody) and
        ($savetofile or $write or $type1)
}

rule JScript_EXE_Download_Pattern
{
    meta:
        description = "Detects JScript downloading executable files"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Critical"
        confidence = "0.90"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $exe = ".exe" nocase
        $http = "http" nocase
        $xmlhttp = "XMLHTTP" nocase
        $responsebody = "responseBody" nocase
        $open = ".open" nocase
        $send = ".send" nocase

    condition:
        $exe and ($http or $xmlhttp) and $responsebody and $open and $send
}

rule JScript_WSH_Sleep_Evasion
{
    meta:
        description = "Detects JScript using WScript.Sleep for evasion"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1497.003"
        category = "evasion"

    strings:
        $sleep = "WScript.Sleep" nocase
        $shell = "WScript.Shell" nocase
        $xmlhttp = "XMLHTTP" nocase
        $adodb = "ADODB" nocase
        $run = ".Run" nocase

        // Long sleep values
        $sleep_long = /WScript\.Sleep\s*\(\s*\d{4,}\s*\)/i

    condition:
        ($sleep or $sleep_long) and
        ($shell or $run or $xmlhttp or $adodb)
}

rule JScript_HTTP_200_Check
{
    meta:
        description = "Detects JScript checking HTTP 200 status before payload execution"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $status200_1 = /\.status\s*==\s*200/
        $status200_2 = /\.status\s*===\s*200/
        $statusok = ".statusText" nocase

        $xmlhttp = "XMLHTTP" nocase
        $responsebody = "responseBody" nocase
        $adodb = "ADODB" nocase

    condition:
        ($status200_1 or $status200_2 or $statusok) and
        $xmlhttp and ($responsebody or $adodb)
}

