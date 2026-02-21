# Last modified: 2025-12-31T04:44:21.131431+00:00
FROM demisto/python3-deb:3.12.12.6493338

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
    npm \
&& npm install -g tar@7.5.4 @isaacs/brace-expansion@5.0.1 \
&& gem install aquatone \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
    npm \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler