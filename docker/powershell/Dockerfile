# Last modified: 2023-02-20T00:14:39.948801+00:00
FROM mcr.microsoft.com/powershell:preview-7.4-alpine-3.15

# Set timezone to Etc/UTC for backwards comp
RUN cp /usr/share/zoneinfo/Etc/UTC /etc/localtime

RUN addgroup -g 4000 demisto \
  && adduser -u 4000 -G demisto -D demisto -s /bin/sh
