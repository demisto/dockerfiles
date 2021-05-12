
FROM demisto/python3:3.9.4.19537

COPY requirements.txt .

COPY --from=golang:1.16-alpine /usr/local/go/ /usr/local/go/

# Configure Go
ENV GOPATH="/usr/local/go"
ENV PATH="/usr/local/go/bin:${PATH}"

RUN apk --update add --no-cache --virtual .build-dependencies build-base gcc wget python3-dev py3-pip git && \
    pip install --no-cache-dir -r requirements.txt && \
    go get -u github.com/rakyll/hey && \
    apk del .build-dependencies

RUN apk --update add --no-cache libstdc++
