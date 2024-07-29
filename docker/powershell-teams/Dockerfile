
FROM demisto/powershell-ubuntu:7.4.1.86201

RUN pwsh -c "Install-Module MicrosoftTeams -Force"
RUN pwsh -c "Uninstall-Module -Name system.text.regularexpressions -AllVersions -Force"