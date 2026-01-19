rule rule_017_Shell_Script_Privilege_Escalation_User_Creation_Pattern {
    meta:
        description = "Shell script with user creation and privilege escalation patterns"
        severity = "High"
        confidence = "0.82"
        mitre_technique = "T1548.001"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "7aed6f79239d5839,d771a672eae7ef61"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // User/group creation commands
        $user1 = "adduser" nocase
        $user2 = "useradd" nocase
        $user3 = "groupadd" nocase
        $user4 = "usermod" nocase
        
        // Permission modification
        $perm1 = "chmod u+s" nocase
        $perm2 = "chmod g+s" nocase
        $perm3 = "chmod +s" nocase
        $perm4 = "chown" nocase
        
        // Privilege-related paths and operations
        $priv1 = "/etc/passwd" nocase
        $priv2 = "/etc/shadow" nocase
        $priv3 = "setuid" nocase
        $priv4 = "setgid" nocase
        $priv5 = "sudo" nocase
        
        // Shell assignment or execution
        $shell1 = "/bin/sh" nocase
        $shell2 = "/bin/bash" nocase
        $shell3 = "SHELL=" nocase

    condition:
        any of ($user*) and any of ($perm*) and any of ($priv*) and any of ($shell*)
}