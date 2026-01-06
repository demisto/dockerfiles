rule rule_027_Suspicious_Shell_Chroot_Environment_Setup {
    meta:
        description = "Shell script setting up chroot execution environment"
        severity = "Medium"
        confidence = "0.75" 
        mitre_technique = "T1055"
        author = "Script Sentinel"
    
    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "90bbad31c691c735"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Chroot operations
        $chroot1 = "mkchroot" nocase
        $chroot2 = "chroot " nocase
        $chroot3 = "dochroot" nocase
        
        // Mount operations for isolation
        $mount1 = "mount -t ramfs" nocase
        $mount2 = "umount -l" nocase
        
        // Device node creation
        $device1 = "mknod " nocase
        $device2 = "/dev/tty" nocase
        $device3 = "/dev/null" nocase
        
        // Directory structure setup
        $setup1 = "mkdir -p " nocase
        $setup2 = "tmpdir4chroot" nocase
        
        // Execution in chroot
        $exec1 = "chmod +x " nocase
        $exec2 = "/test.sh" nocase
        
        // Shell indicators  
        $shell1 = "#!/bin/sh" nocase
        $shell2 = "#!/bin/bash" nocase
    
    condition:
        any of ($shell*) and
        any of ($chroot*) and
        any of ($mount*) and
        any of ($device*) and
        any of ($setup*) and
        any of ($exec*)
}