
FROM demisto/python3-deb:3.10.7.35175

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
  ruby-dev \
&& gem install aquatone \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  ruby-dev \
&& rm -rf /var/lib/apt/lists/*