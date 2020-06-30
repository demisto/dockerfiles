FROM demisto/powershell:7.0.1.9103

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -ErrorAction Stop -Scope AllUsers VMware.PowerCLI,PowerNSX,PowervRA

