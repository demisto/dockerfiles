FROM demisto/powershell:6.2.1.1729

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module VMware.PowerCLI,PowerNSX,PowervRA

