/*
    YARA Rule: JScript XOR Obfuscation Patterns

    Detects heavily obfuscated JScript malware that uses
    variable fragmentation and XOR-based string reconstruction.

    MITRE ATT&CK: T1027 (Obfuscated Files or Information)
*/

rule JScript_Heavy_Variable_Fragmentation
{
    meta:
        description = "Detects JScript with heavy variable fragmentation obfuscation"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Many variable declarations with short strings
        $var_pattern = /var\s+[a-zA-Z][a-zA-Z0-9_]{0,25}\s*=\s*["'][a-zA-Z0-9_\.\/\-\%:]{1,15}["']/

        // Suspicious string fragments that appear in malware
        $frag_scr = ".scr" nocase
        $frag_exe = ".exe" nocase
        $frag_xml = "XML" nocase
        $frag_http = "http" nocase
        $frag_save = "save" nocase
        $frag_run = "Run" nocase
        $frag_shell = "Shell" nocase
        $frag_stream = "ream" nocase
        $frag_file = "File" nocase
        $frag_temp = "TEMP" nocase
        $frag_body = "Body" nocase
        $frag_resp = "espo" nocase

    condition:
        #var_pattern > 20 and 4 of ($frag_*)
}

rule JScript_XOR_Deobfuscation_Loop
{
    meta:
        description = "Detects JScript using XOR in a loop for deobfuscation"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // XOR operation
        $xor = "^"

        // Loop structures
        $for = /for\s*\(/
        $while = /while\s*\(/

        // String/char operations
        $charcodeat = "charCodeAt" nocase
        $fromcharcode = "fromCharCode" nocase
        $charat = "charAt" nocase

        // Suspicious extensions
        $scr = ".scr" nocase
        $exe = ".exe" nocase

    condition:
        $xor and ($for or $while) and
        ($charcodeat or $fromcharcode or $charat) and
        ($scr or $exe)
}

rule JScript_Fragment_Reassembly
{
    meta:
        description = "Detects JScript reassembling fragmented strings"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Variable concatenation patterns (multiple vars added together)
        $concat_chain = /\w+\s*\+\s*\w+\s*\+\s*\w+\s*\+\s*\w+/

        // Suspicious fragments
        $frag_adodb = "ADODB" nocase
        $frag_stream = "Stream" nocase
        $frag_xmlhttp = "XMLHTTP" nocase
        $frag_msxml = "MSXML" nocase
        $frag_script = "Script" nocase
        $frag_shell = "Shell" nocase

        // Malicious extensions
        $scr = ".scr" nocase
        $exe = ".exe" nocase

    condition:
        #concat_chain >= 3 and
        2 of ($frag_*) and
        ($scr or $exe)
}

rule JScript_Scattered_Malware_Keywords
{
    meta:
        description = "Detects JScript with scattered malware keywords across variables"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Fragmented keywords commonly seen in WSH droppers
        $kw_scr = ".scr" nocase
        $kw_xmlh = "XMLH" nocase
        $kw_msxml = "MSXML" nocase
        $kw_save = "save" nocase
        $kw_file = "File" nocase
        $kw_run = "Run" nocase
        $kw_shell = "Shell" nocase
        $kw_stream = "ream" nocase
        $kw_resp = "resp" nocase
        $kw_body = "Body" nocase
        $kw_http = "http" nocase
        $kw_temp = "TEMP" nocase
        $kw_adodb = "ADODB" nocase

        // Variable assignment pattern
        $var_assign = /=\s*["'][a-zA-Z]{2,10}["']/

    condition:
        #var_assign > 15 and 5 of ($kw_*)
}

rule JScript_SCR_Fragmented_Dropper
{
    meta:
        description = "Detects fragmented JScript dropper targeting .scr extension"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Critical"
        confidence = "0.90"
        mitre_technique = "T1105"
        category = "dropper"

    strings:
        $scr = ".scr" nocase

        // Fragmented keywords
        $frag1 = /=\s*["']ADODB["']/i
        $frag2 = /=\s*["']Stream["']/i
        $frag3 = /=\s*["']XMLH["']/i
        $frag4 = /=\s*["']save["']/i
        $frag5 = /=\s*["']File["']/i
        $frag6 = /=\s*["']resp["']/i
        $frag7 = /=\s*["']Body["']/i

    condition:
        $scr and 3 of ($frag*)
}

rule JScript_Jquery_Variable_Obfuscation
{
    meta:
        description = "Detects JScript using jQuery-like variable names for obfuscation"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // jQuery-like variable names commonly used in obfuscated malware
        $jq1 = "dirruns" nocase
        $jq2 = "cssHooks" nocase
        $jq3 = "clearQueue" nocase
        $jq4 = "beforeSend" nocase
        $jq5 = "uniqueSort" nocase
        $jq6 = "dataUser" nocase
        $jq7 = "defaultView" nocase
        $jq8 = "hasCompare" nocase
        $jq9 = "selectors" nocase
        $jq10 = "parentWindow" nocase

        // Malicious indicators
        $mal_scr = ".scr" nocase
        $mal_xml = "XML" nocase
        $mal_save = "save" nocase

    condition:
        4 of ($jq*) and 2 of ($mal_*)
}

rule JScript_Numeric_Variable_Obfuscation
{
    meta:
        description = "Detects JScript mixing numeric and string variables for obfuscation"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1027"
        category = "obfuscation"

    strings:
        // Pattern: var name = number;
        $num_var = /var\s+[a-zA-Z]\w*\s*=\s*\d{2,4}\s*[,;]/

        // Pattern: var name = "string";
        $str_var = /var\s+[a-zA-Z]\w*\s*=\s*["'][^"']+["']\s*[,;]/

        // Malicious indicators
        $scr = ".scr" nocase
        $exe = ".exe" nocase
        $xml = "XML" nocase
        $http = "http" nocase

    condition:
        #num_var > 5 and #str_var > 10 and 2 of ($scr, $exe, $xml, $http)
}

