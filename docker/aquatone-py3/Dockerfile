
FROM demisto/chromium:1.0.0.35353

ADD https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip /usr/local/bin/aquatone.zip

RUN apt-get update && apt-get install -y --no-install-recommends \
  zip \
  unzip \
  && unzip /usr/local/bin/aquatone.zip -d /usr/local/bin \
  && chmod +x /usr/local/bin/aquatone  \
  && rm -rf /usr/local/bin/aquatone.zip