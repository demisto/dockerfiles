FROM demisto/powershell:7.4.2.103657

SHELL [ "pwsh", "-command" ]

RUN Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
RUN Install-Module -ErrorAction Stop -Scope AllUsers VMware.PowerCLI,PowerNSX,PowervRA

