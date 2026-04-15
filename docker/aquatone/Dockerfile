# Last modified: 2026-04-12T13:04:04.978663+00:00
FROM demisto/python3-deb:3.12.13.8167125

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
&& gem install aquatone \
&& gem install httparty -v '>= 0.24.0' \
&& gem install rake -v '>= 12.3.3' \
&& gem install rexml -v '>= 3.2.5' \
&& gem uninstall httparty -v '< 0.24.0' --force --ignore-dependencies \
&& gem uninstall rake -v '< 13.4.0' --force --ignore-dependencies \
&& gem uninstall rexml -v '< 3.4.0' --force --ignore-dependencies \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler