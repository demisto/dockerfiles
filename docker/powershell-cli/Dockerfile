FROM demisto/powershell:7.1.1.16151

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -ErrorAction Stop -Scope AllUsers VMware.PowerCLI,PowerNSX,PowervRA

