# Last modified: 2026-02-11T15:18:34.933506+00:00
FROM demisto/python3-deb:3.12.12.7090913

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
    git \
&& gem install specific_install \
&& gem specific_install -l https://github.com/jnunemaker/httparty.git -b 0529bcd \
&& gem install aquatone \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
    git \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler