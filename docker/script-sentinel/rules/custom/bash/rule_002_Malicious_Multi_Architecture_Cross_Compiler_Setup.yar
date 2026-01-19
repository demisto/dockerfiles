rule rule_002_Malicious_Multi_Architecture_Cross_Compiler_Setup {
    /*
     * Detects installation of cross-compilers for multiple embedded architectures
     * commonly used by IoT malware builders and botnet compilation frameworks.
     * 
     * Example match:
     *   cross-compiler-armv4l.tar.bz2, cross-compiler-mips.tar.bz2, etc.
     *   export PATH=$PATH:/etc/xcompile/armv4l/bin
     */
    meta:
        description = "Multi-architecture cross-compiler setup for embedded systems"
        severity = "Medium"
        confidence = "0.82"
        mitre_technique = "T1588.002"
        author = "Script Sentinel"

    // Provenance (auto-generated, do not edit)
    generated_by = "sentinel-generate"
    generated_at = "2025-12-28"
    source_scripts = "0d92289f250b55c7"
    approved_by = "Script Sentinel Team"
    approved_at = "2025-12-28"
    strings:
        // Cross-compiler archive patterns
        $cc1 = "cross-compiler-armv" nocase
        $cc2 = "cross-compiler-mips" nocase
        $cc3 = "cross-compiler-powerpc" nocase
        $cc4 = "cross-compiler-sparc" nocase
        $cc5 = "cross-compiler-m68k" nocase
        $cc6 = "cross-compiler-sh4" nocase
        
        // Xcompile directory setup
        $xcompile1 = "/etc/xcompile" nocase
        $xcompile2 = "mkdir /etc/xcompile" nocase
        
        // PATH exports for multiple architectures
        $path_export = /export PATH=\$PATH:\/etc\/xcompile\/[a-z0-9]+\/bin/ nocase
        
        // Multiple architecture extraction
        $extract = /tar.*-jxf.*cross-compiler/ nocase

    condition:
        (
            // At least 3 different architectures
            (
                ($cc1 and $cc2) or ($cc1 and $cc3) or ($cc1 and $cc4) or
                ($cc2 and $cc3) or ($cc2 and $cc4) or ($cc3 and $cc4)
            )
            and any of ($xcompile*)
        ) or
        (
            $path_export and $extract and any of ($cc*)
        )
}