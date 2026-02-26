/*
    YARA Rule: JScript HTTP Download Patterns

    Detects JScript/WSH malware using MSXML HTTP objects
    for downloading payloads.

    MITRE ATT&CK: T1105 (Ingress Tool Transfer)
*/

rule JScript_MSXML_HTTP_Download
{
    meta:
        description = "Detects JScript using MSXML HTTP for downloads"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1105"
        category = "network"

    strings:
        $msxml1 = "MSXML2.XMLHTTP" nocase
        $msxml2 = "Microsoft.XMLHTTP" nocase
        $msxml3 = "MSXML2.ServerXMLHTTP" nocase
        $open = ".open" nocase
        $send = ".send" nocase
        $responsebody = "responseBody" nocase
        $responsetext = "responseText" nocase

    condition:
        ($msxml1 or $msxml2 or $msxml3) and
        $open and $send and
        ($responsebody or $responsetext)
}

rule JScript_HTTP_Download_Execute
{
    meta:
        description = "Detects JScript downloading and executing payloads"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Critical"
        confidence = "0.95"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $msxml1 = "MSXML2.XMLHTTP" nocase
        $msxml2 = "Microsoft.XMLHTTP" nocase
        $msxml3 = "MSXML2.ServerXMLHTTP" nocase
        $createobject = "CreateObject" nocase
        $responsebody = "responseBody" nocase
        $savetofile = "saveToFile" nocase
        $run = ".Run" nocase
        $exe = ".exe" nocase
        $scr = ".scr" nocase

    condition:
        ($msxml1 or $msxml2 or $msxml3) and $createobject and $responsebody and
        ($savetofile or $run) and
        ($exe or $scr)
}

rule JScript_URL_String_Construction
{
    meta:
        description = "Detects JScript with obfuscated URL string construction"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.7"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        $http_split = /["']ht["']\s*\+\s*["']tp/i
        $https_split = /["']htt["']\s*\+\s*["']ps/i
        $colon_slash = /["']:\/\/["']/
        $dot_com = /["']\.com["']/
        $dot_exe = /["']\.exe["']/

    condition:
        ($http_split or $https_split) and
        ($colon_slash or $dot_com or $dot_exe)
}
