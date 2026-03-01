/*
    YARA Rule: JScript Obfuscation Patterns

    Detects heavily obfuscated JScript malware using:
    - String fragment variables
    - Variable name obfuscation
    - String concatenation patterns

    MITRE ATT&CK: T1027 (Obfuscated Files or Information)
*/

rule JScript_String_Fragment_Obfuscation
{
    meta:
        description = "Detects JScript with string fragments in variables for obfuscation"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Fragmented common malware strings
        $frag_resp1 = /["']esponse["']/ nocase
        $frag_resp2 = /["']onseBo["']/ nocase
        $frag_body = /["']ody["']/ nocase
        $frag_xml1 = /["']MSX["']/ nocase
        $frag_xml2 = /["']XMLH["']/ nocase
        $frag_http = /["']HTTP["']/ nocase
        $frag_save = /["']aveTo["']/ nocase
        $frag_file = /["']oFile["']/ nocase
        $frag_run = /["']\.Run["']/ nocase
        $frag_shell = /["']hell["']/ nocase
        $frag_script = /["']Script["']/ nocase
        $frag_create = /["']Cre["']/ nocase
        $frag_object = /["']eObj["']/ nocase
        $frag_adodb = /["']ADODB["']/ nocase
        $frag_stream = /["']ream["']/ nocase

        // File extensions often targeted
        $ext_scr = ".scr" nocase
        $ext_exe = ".exe" nocase

    condition:
        (
            ($frag_resp1 or $frag_resp2) and $frag_body
        ) or
        (
            $frag_xml1 and ($frag_xml2 or $frag_http)
        ) or
        (
            ($frag_save or $frag_file) and ($frag_adodb or $frag_stream)
        ) or
        (
            ($frag_create and $frag_object) and ($frag_shell or $frag_run)
        ) or
        (
            3 of ($frag_*) and ($ext_scr or $ext_exe)
        )
}

rule JScript_Variable_String_Concatenation
{
    meta:
        description = "Detects JScript using variable string concatenation to evade detection"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // String concatenation patterns for common objects
        $concat1 = /["']Create["']\s*\+\s*["']Object["']/i
        $concat2 = /["']WScript["']\s*\+\s*["']\.Shell["']/i
        $concat3 = /["']MSXML2["']\s*\+\s*["']\.XMLHTTP["']/i
        $concat4 = /["']ADODB["']\s*\+\s*["']\.Stream["']/i
        $concat5 = /["']Shell["']\s*\+\s*["']\.Application["']/i
        $concat6 = /["']Scripting["']\s*\+\s*["']\.FileSystem["']/i
        $concat7 = /["']\.["']\s*\+\s*["']Run["']/i
        $concat8 = /["']response["']\s*\+\s*["']Body["']/i
        $concat9 = /["']save["']\s*\+\s*["']ToFile["']/i

    condition:
        any of them
}

rule JScript_Many_Variable_Fragments
{
    meta:
        description = "Detects JScript with many variable assignments containing string fragments"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Pattern: var name = "short_string";
        $var_pattern = /var\s+[a-zA-Z_]\w{0,20}\s*=\s*["'][^"']{1,10}["']\s*[,;]/

        // Suspicious fragments that may appear
        $sus1 = "esponse" nocase
        $sus2 = "aveToFile" nocase
        $sus3 = ".scr" nocase
        $sus4 = "xmlhttp" nocase
        $sus5 = "ExpandEnv" nocase
        $sus6 = "reateObj" nocase

    condition:
        #var_pattern > 15 and 2 of ($sus*)
}

rule JScript_Eval_Concatenated_String
{
    meta:
        description = "Detects JScript evaluating concatenated strings"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        $eval = "eval" nocase
        $new_func = /new\s+Function\s*\(/i

        // Variable concatenation in eval context
        $concat_vars = /eval\s*\(\s*\w+\s*\+\s*\w+/i
        $concat_array = /eval\s*\(\s*\[.*\]\.join/i

        // Suspicious strings that might be reconstructed
        $xmlhttp = "XMLHTTP" nocase
        $adodb = "ADODB" nocase
        $wscript = "WScript" nocase

    condition:
        ($eval or $new_func) and ($concat_vars or $concat_array) and any of ($xmlhttp, $adodb, $wscript)
}

