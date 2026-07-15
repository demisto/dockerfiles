# Last modified: 2026-06-14T04:48:37.982929+00:00
FROM demisto/python3-deb:3.12.13.10116658

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
&& gem install aquatone \
&& find /var/lib/gems /usr/lib/ruby/gems /usr/local/lib/ruby/gems -name "aquatone-*.gemspec" -exec sed -i 's/0.14/0.24/g' {} + 2>/dev/null || true \
&& gem install httparty -v 0.24.0 \
&& gem uninstall httparty -v 0.14.0 --ignore-dependencies --force \
&& apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
&& rm -rf /var/lib/apt/lists/* \
&& find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete\
&& gem install bundler