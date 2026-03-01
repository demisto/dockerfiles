/*
    YARA Rule: JScript ActiveX and Scripting Objects

    Detects JScript/WSH malware using ActiveXObject and
    Scripting.FileSystemObject for malicious operations.

    MITRE ATT&CK: T1059.007 (JavaScript), T1106 (Native API)
*/

rule JScript_ActiveXObject_Shell
{
    meta:
        description = "Detects JScript using ActiveXObject for shell access"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.007"
        category = "execution"

    strings:
        $activex = "ActiveXObject" nocase
        $wscript_shell = "WScript.Shell" nocase
        $shell_app = "Shell.Application" nocase
        $run = ".Run" nocase
        $exec = ".Exec" nocase

    condition:
        $activex and
        ($wscript_shell or $shell_app) and
        ($run or $exec)
}

rule JScript_FileSystemObject_Operations
{
    meta:
        description = "Detects JScript using FileSystemObject for file operations"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "Medium"
        confidence = "0.75"
        mitre_technique = "T1106"
        category = "file_ops"

    strings:
        $fso = "Scripting.FileSystemObject" nocase
        $createtext = "CreateTextFile" nocase
        $writeline = "WriteLine" nocase
        $deletefile = "DeleteFile" nocase
        $copyfile = "CopyFile" nocase
        $movefile = "MoveFile" nocase

    condition:
        $fso and
        (
            ($createtext and $writeline) or
            $deletefile or
            ($copyfile or $movefile)
        )
}

rule JScript_WMI_Process_Create
{
    meta:
        description = "Detects JScript using WMI to create processes"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.9"
        mitre_technique = "T1047"
        category = "execution"

    strings:
        $wmi1 = "winmgmts:" nocase
        $wmi2 = "WbemScripting" nocase
        $win32process = "Win32_Process" nocase
        $create = ".Create" nocase
        $execquery = "ExecQuery" nocase

    condition:
        ($wmi1 or $wmi2) and
        ($win32process or $create or $execquery)
}

rule JScript_Scheduled_Task_Creation
{
    meta:
        description = "Detects JScript creating scheduled tasks for persistence"
        author = "Script Sentinel Team"
        date = "2025-12-28"
        severity = "High"
        confidence = "0.9"
        mitre_technique = "T1053.005"
        category = "persistence"

    strings:
        $schedule = "Schedule.Service" nocase
        $taskservice = "TaskService" nocase
        $newtask = "NewTask" nocase
        $registertask = "RegisterTask" nocase
        $schtasks = "schtasks" nocase
        $run = ".Run" nocase

    condition:
        ($schedule or $taskservice) and ($newtask or $registertask) or
        ($schtasks and $run)
}
