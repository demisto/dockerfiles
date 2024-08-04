# Last modified: 2023-11-17T00:12:42.649505+00:00
FROM mcr.microsoft.com/powershell:7.4-ubuntu-20.04

# For the `no supported WSMan client library was found` error when using Ubuntu 20+
RUN apt-get update -y
RUN sh -c "yes | pwsh -Command 'Install-Module -Name PSWSMan'"
RUN pwsh -Command 'Install-WSMan'





#
# RUN sh -c "yes | pwsh -Command 'Install-Module -Name newtonsoft.json -RequiredVersion 13.0.1'"
# RUN sh -c "yes | pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet'"

# RUN sh -c "y | pwsh -Command 'Install-Package -Name newtonsoft.json -ProviderName NuGet -RequiredVersion 13.0.1'"
# RUN sh -c "y | pwsh -Command 'Get-Package -Name newtonsoft.json -RequiredVersion 12.0.3 -ProviderName NuGet | Uninstall-Package'"
#



RUN apt update && apt install netbase -y
# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

RUN rm /opt/microsoft/powershell/7/Newtonsoft.Json.dll

# RUN sh -c "yes | pwsh -Command 'Uninstall-Module -Force -Name newtonsoft.json'"
# RUN pwsh -Command 'Uninstall-Module -Force -Name newtonsoft.json'

# RUN sh -c "yes | pwsh -Command 'Install-Module -Name newtonsoft.json -MinimumVersion 13.0.1'"

# RUN pwsh -command 'Install-Module -Force -Name newtonsoft.json -MinimumVersion 13.0.1'
# RUN pwsh -command 'Import-Module -Name newtonsoft.json'



# RUN sh -c "y | pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet -RequiredVersion 12.0.3'"

# RUN sudo /root/.local/share/powershell -c sh -c "y | pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet -RequiredVersion 12.0.3'"
# RUN pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet -RequiredVersion 12.0.3'


# RUN /bin/sh -c sh -c "y | pwsh -Command 'Install-Package -Name newtonsoft.json -ProviderName NuGet -RequiredVersion 13.0.1'"









# build passed
# RUN /bin/sh -c sh -c "y | pwsh -Command 'Uninstall-Package -Name newtonsoft.json -ProviderName NuGet'"
# RUN /bin/sh -c sh -c "yes | pwsh -Command 'Uninstall-Package -Name system.formats.asn1 -ProviderName NuGet'"
# RUN /bin/sh -c sh -c "yes | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"
# RUN /bin/sh -c sh -c "yes | pwsh -Command 'Uninstall-Module -Name system.formats.asn1 -AllVersions'"
# RUN /bin/sh -c "yes | pwsh -Command 'Uninstall-Module -Name system.formats.asn1 -AllVersions'"
#
# RUN sh -c "y | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"
# # RUN /bin/sh -c "y | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"
#
#



# Uninstall-Package: No package found for 'system.formats.asn1'.
# RUN /bin/sh -c "yes | pwsh -Command 'Uninstall-Package -Name system.formats.asn1 -ProviderName NuGet'"

# Uninstall-Package: No package found for 'system.formats.asn1
#RUN /bin/sh -c "yes | pwsh -Command 'Uninstall-Package -Name system.formats.asn1'"

# Uninstall-Package: No package found for 'system.formats.asn1
#RUN sh -c "yes | pwsh -Command 'Uninstall-Package -Name system.formats.asn1'"


# /opt/microsoft/powershell/7: Permission denied
# RUN /opt/microsoft/powershell/7 -c "y | pwsh -Command 'Install-Package -Name system.formats.asn1 -ProviderName NuGet -RequiredVersion 8.0.1'"



# Set timezone to Etc/UTC for backwards comp. See: https://github.com/regebro/tzlocal/issues/101
RUN echo 'Etc/UTC' > /etc/timezone \
&& dpkg-reconfigure --frontend noninteractive tzdata

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto

