
FROM demisto/python3-deb:3.11.9.103065

COPY requirements.txt .
# downloaded from https://hey-release.s3.us-east-2.amazonaws.com/hey_linux_amd64 (version 0.1.4)
# see: https://github.com/rakyll/hey
COPY hey_linux_amd64 /usr/bin/hey

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/* \
&& rm ./usr/lib/ruby/gems/2.7.0/specifications/default/bundler-2.1.4.gemspec \
&& gem install bundler
