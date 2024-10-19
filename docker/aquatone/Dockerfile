# Last modified: 2024-10-19T00:49:42.467999+00:00
FROM demisto/python3-deb:3.11.10.113802

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
&& rm ./usr/lib/ruby/gems/2.7.0/specifications/default/bundler-2.1.4.gemspec \
&& gem install bundler