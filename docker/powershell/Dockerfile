# Last modified: Sun, 29 Aug 2021 16:25:44 +0000
FROM mcr.microsoft.com/powershell:7.1.4-alpine-3.12-20210819

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
