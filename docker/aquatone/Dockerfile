FROM demisto/python3-deb:3.12.13.7742802

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    build-essential \
    ruby-dev \
    rubygems \
 && gem install aquatone \
 && gem install httparty -v 0.24.2 \
 && gem install rexml -v 3.4.4 \
 && gem install rake -v 13.2.1 \
 && find /usr/lib/ruby/gems/*/specifications/default/ -name "bundler-*.gemspec" -delete \
 && gem install bundler \
 && apt-get purge -y --auto-remove \
    build-essential \
    ruby-dev \
    rubygems \
 && rm -rf /var/lib/apt/lists/*
