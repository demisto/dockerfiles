FROM demisto/powershell:6.2.3.5563

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module VMware.PowerCLI,PowerNSX,PowervRA

