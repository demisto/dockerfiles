# Last modified: 2024-07-14T00:12:45.520896+00:00
FROM mcr.microsoft.com/powershell:7.4-alpine-3.17

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh \
  && apk update \
  && apk upgrade \
  && apk del less


# build passed
RUN /bin/sh -c sh -c "y | pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet'"
RUN /bin/sh -c sh -c "yes | pwsh -Command 'Uninstall-Package -Name system.formats.asn1 -ProviderName NuGet'"
RUN /bin/sh -c sh -c "yes | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"
RUN /bin/sh -c sh -c "yes | pwsh -Command 'Uninstall-Module -Name system.formats.asn1 -AllVersions'"
RUN /bin/sh -c "yes | pwsh -Command 'Uninstall-Module -Name system.formats.asn1 -AllVersions'"

RUN sh -c "y | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"