# Last modified: 2026-01-18T10:51:45.697772+00:00

FROM demisto/powershell-ubuntu:7.5.0.6704649

USER root

RUN pwsh -c "Install-Module MicrosoftTeams -Force"

ENV DEFAULT_USER="demisto"

USER $DEFAULT_USER
WORKDIR /home/$DEFAULT_USER
