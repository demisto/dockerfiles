# Last modified: Sun, 29 Aug 2021 13:16:52 +0000
FROM alpine:3.16.0

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY localtime /etc/localtime

RUN apk --update add --no-cache cowsay --repository=http://dl-cdn.alpinelinux.org/alpine/edge/testing

RUN addgroup -g 4000 demisto \
    && adduser -u 4000 -G demisto -D demisto -s /bin/sh

COPY cowcow /bin/cowcow
RUN ["chmod", "+x", "/bin/cowcow"]

RUN cd /usr/share/cows

ENTRYPOINT ["/bin/cowcow"]

CMD = ["shalom"]
