FROM demisto/powershell:7.1.3.20923

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -ErrorAction Stop -Scope AllUsers VMware.PowerCLI,PowerNSX,PowervRA

