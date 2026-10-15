# Last modified: 2026-10-15T05:10:17.399297+00:00
FROM mcr.microsoft.com/powershell:7.5-alpine-3.20

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh \
  && apk update \
  && apk upgrade \
  && apk -X https://dl-cdn.alpinelinux.org/alpine/edge/main upgrade \
    openssh-client-common \
    openssh-client-default \
    openssh-keygen \
  && apk del less

RUN wget -q https://api.nuget.org/v3-flatcontainer/system.security.cryptography.xml/9.0.21/system.security.cryptography.xml.9.0.21.nupkg -O /tmp/cryptography-xml.nupkg \
  && unzip -o /tmp/cryptography-xml.nupkg lib/net9.0/System.Security.Cryptography.Xml.dll -d /tmp/nuget \
  && cp /tmp/nuget/lib/net9.0/System.Security.Cryptography.Xml.dll /opt/microsoft/powershell/7/System.Security.Cryptography.Xml.dll \
  && rm -rf /tmp/cryptography-xml.nupkg /tmp/nuget \
  && sed -i \
    -e 's|"System.Security.Cryptography.Xml": "9.0.1"|"System.Security.Cryptography.Xml": "9.0.21"|g' \
    -e 's|System.Security.Cryptography.Xml/9.0.1|System.Security.Cryptography.Xml/9.0.21|g' \
    -e 's|system.security.cryptography.xml/9.0.1|system.security.cryptography.xml/9.0.21|g' \
    -e 's|system.security.cryptography.xml.9.0.1.nupkg.sha512|system.security.cryptography.xml.9.0.21.nupkg.sha512|g' \
    /opt/microsoft/powershell/7/pwsh.deps.json \
  && wget -q https://api.nuget.org/v3-flatcontainer/system.security.cryptography.pkcs/9.0.21/system.security.cryptography.pkcs.9.0.21.nupkg -O /tmp/cryptography-pkcs.nupkg \
  && unzip -o /tmp/cryptography-pkcs.nupkg lib/net9.0/System.Security.Cryptography.Pkcs.dll -d /tmp/nuget \
  && cp /tmp/nuget/lib/net9.0/System.Security.Cryptography.Pkcs.dll /opt/microsoft/powershell/7/System.Security.Cryptography.Pkcs.dll \
  && rm -rf /tmp/cryptography-pkcs.nupkg /tmp/nuget \
  && sed -i \
    -e 's|"System.Security.Cryptography.Pkcs": "9.0.1"|"System.Security.Cryptography.Pkcs": "9.0.21"|g' \
    -e 's|System.Security.Cryptography.Pkcs/9.0.1|System.Security.Cryptography.Pkcs/9.0.21|g' \
    -e 's|system.security.cryptography.pkcs/9.0.1|system.security.cryptography.pkcs/9.0.21|g' \
    -e 's|system.security.cryptography.pkcs.9.0.1.nupkg.sha512|system.security.cryptography.pkcs.9.0.21.nupkg.sha512|g' \
    /opt/microsoft/powershell/7/pwsh.deps.json
