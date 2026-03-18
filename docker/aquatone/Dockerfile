# Last modified: 2026-03-18T13:06:45.850759+00:00
FROM demisto/python3-deb:3.12.13.7742802

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
&& gem install aquatone \
&& gem install httparty -v '>= 0.24.0' \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler