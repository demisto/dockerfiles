# Last modified: 2026-04-26T18:44:50.376392+00:00

FROM demisto/powershell-ubuntu:7.5.0.8425368

USER root

RUN pwsh -c "Install-Module MicrosoftTeams -Force"

ENV DEFAULT_USER="demisto"

USER $DEFAULT_USER
WORKDIR /home/$DEFAULT_USER
