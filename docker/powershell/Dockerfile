# Last modified: 2022-09-16T00:19:01.881130+00:00
FROM mcr.microsoft.com/powershell:7.2.2-alpine-3.14-20220318

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
