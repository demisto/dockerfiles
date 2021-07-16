# Last modified: Fri, 16 Jul 2021 10:59:19 +0000
FROM mcr.microsoft.com/powershell:7.1.3-alpine-3.12-20210616

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
