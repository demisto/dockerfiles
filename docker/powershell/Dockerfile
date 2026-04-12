# Last modified: 2026-04-12T08:19:31.369898+00:00
FROM mcr.microsoft.com/powershell:7.5-alpine-3.20

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh \
  && apk update \
  && apk upgrade \
  && apk del less
