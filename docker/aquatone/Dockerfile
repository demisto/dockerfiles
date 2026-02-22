# Last modified: 2025-12-31T04:44:21.131431+00:00
FROM demisto/python3-deb:3.12.12.6493338

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    libssl3 \
    openssl \
    gnupg \
&& rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "urllib3>=2.6.3" \
    "cryptography>=46.0.5" \
    "jaraco.context>=6.1.0" \
    "wheel>=0.46.2"

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
&& gem install aquatone \
&& gem install httparty \
&& gem update httparty \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler