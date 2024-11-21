# Last modified: 2024-11-21T00:17:16.870390+00:00
FROM mcr.microsoft.com/powershell:7.4-alpine-3.20

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh \
  && apk update \
  && apk upgrade \
  && apk del less
