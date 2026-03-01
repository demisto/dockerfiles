/*
    YARA Rule: JScript Environment and File Operations

    Detects JScript malware using environment strings and
    file system operations without explicit shell execution.

    MITRE ATT&CK: T1083 (File and Directory Discovery), T1005 (Data from Local System)
*/

rule JScript_Env_Strings_Operations
{
    meta:
        description = "Detects JScript using environment strings with file operations"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1083"
        category = "discovery"

    strings:
        $expand = "ExpandEnvironmentStrings" nocase

        // Environment variables
        $temp = "%TEMP%" nocase
        $appdata = "%APPDATA%" nocase
        $localappdata = "%LOCALAPPDATA%" nocase
        $userprofile = "%USERPROFILE%" nocase
        $programdata = "%PROGRAMDATA%" nocase
        $programfiles = "%PROGRAMFILES%" nocase
        $windir = "%WINDIR%" nocase
        $systemroot = "%SYSTEMROOT%" nocase

        // Object creation
        $createobj = "CreateObject" nocase
        $activex = "ActiveXObject" nocase

    condition:
        $expand and 2 of ($temp, $appdata, $localappdata, $userprofile, $programdata, $programfiles, $windir, $systemroot) and
        ($createobj or $activex)
}

rule JScript_Temp_Directory_Access
{
    meta:
        description = "Detects JScript accessing TEMP directory with suspicious operations"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1083"
        category = "discovery"

    strings:
        $temp1 = "%TEMP%" nocase
        $temp2 = "GetSpecialFolder" nocase
        $temp3 = "TemporaryFolder" nocase

        // Operations
        $fso = "FileSystemObject" nocase
        $adodb = "ADODB.Stream" nocase
        $xmlhttp = "XMLHTTP" nocase

        // File extensions often dropped
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $dll = ".dll" nocase

    condition:
        ($temp1 or $temp2 or $temp3) and
        ($fso or $adodb or $xmlhttp) and
        ($exe or $scr or $dll)
}

rule JScript_GetSpecialFolder
{
    meta:
        description = "Detects JScript using GetSpecialFolder for file operations"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.70"
        mitre_technique = "T1083"
        category = "discovery"

    strings:
        $getspecial = "GetSpecialFolder" nocase
        $fso = "FileSystemObject" nocase

        // Folder constants (0=Windows, 1=System, 2=Temp)
        $folder0 = "GetSpecialFolder(0)" nocase
        $folder1 = "GetSpecialFolder(1)" nocase
        $folder2 = "GetSpecialFolder(2)" nocase

        // File operations
        $createfile = "CreateTextFile" nocase
        $copyfile = "CopyFile" nocase
        $movefile = "MoveFile" nocase

    condition:
        $fso and ($getspecial or $folder0 or $folder1 or $folder2) and
        ($createfile or $copyfile or $movefile)
}

rule JScript_BuildPath_Suspicious
{
    meta:
        description = "Detects JScript using BuildPath with suspicious extensions"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1083"
        category = "file_ops"

    strings:
        $buildpath = "BuildPath" nocase
        $fso = "FileSystemObject" nocase

        // Suspicious extensions in BuildPath context
        $exe = ".exe" nocase
        $scr = ".scr" nocase
        $dll = ".dll" nocase
        $bat = ".bat" nocase
        $cmd = ".cmd" nocase
        $vbs = ".vbs" nocase
        $ps1 = ".ps1" nocase

    condition:
        $fso and $buildpath and 2 of ($exe, $scr, $dll, $bat, $cmd, $vbs, $ps1)
}

rule JScript_Random_Filename_Generation
{
    meta:
        description = "Detects JScript generating random filenames for dropped files"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.80"
        mitre_technique = "T1027"
        category = "evasion"

    strings:
        // Random generation
        $random = "Math.random" nocase
        $tostring = ".toString(36)" nocase

        // File operations
        $fso = "FileSystemObject" nocase
        $adodb = "ADODB.Stream" nocase
        $savetofile = "saveToFile" nocase

        // Extensions
        $exe = ".exe" nocase
        $scr = ".scr" nocase

    condition:
        ($random or $tostring) and
        ($fso or $adodb or $savetofile) and
        ($exe or $scr)
}

