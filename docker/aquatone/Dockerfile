# Last modified: 2026-03-26T14:46:11.252923+00:00
FROM demisto/python3-deb:3.12.13.7742802

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
&& gem install aquatone \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler