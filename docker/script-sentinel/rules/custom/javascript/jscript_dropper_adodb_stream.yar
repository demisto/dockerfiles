/*
    YARA Rule: JScript Dropper - ADODB Stream Download Pattern

    Detects JScript/WSH malware that uses ADODB.Stream to download
    and save binary files, commonly seen in dropper malware.

    MITRE ATT&CK: T1059.007 (JavaScript), T1105 (Ingress Tool Transfer)
*/

rule JScript_Dropper_ADODB_Stream_Download
{
    meta:
        description = "Detects JScript dropper using ADODB.Stream for file download and save"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $adodb = "ADODB.Stream" nocase
        $xmlhttp1 = "MSXML2.XMLHTTP" nocase
        $xmlhttp2 = "Microsoft.XMLHTTP" nocase
        $responsebody = "responseBody" nocase
        $savetofile = "saveToFile" nocase
        $write = ".Write" nocase

    condition:
        $adodb and
        ($xmlhttp1 or $xmlhttp2) and
        $responsebody and
        ($savetofile or $write)
}

rule JScript_Dropper_ADODB_Binary_Save
{
    meta:
        description = "Detects JScript dropper saving binary content via ADODB.Stream"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.9"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $adodb = "ADODB.Stream" nocase
        $type_binary = /\.Type\s*=\s*1/
        $savetofile = "SaveToFile" nocase
        $open = ".Open" nocase
        $close = ".Close" nocase

    condition:
        $adodb and $type_binary and $savetofile and ($open or $close)
}
