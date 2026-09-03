FROM demisto/powershell:7.1.3.22925

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -ErrorAction Stop -Scope AllUsers VMware.PowerCLI,PowerNSX,PowervRA


# CIAC-17423 parallel-build POC: touch to include in parallel capacity test
