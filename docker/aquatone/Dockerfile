# Last modified: 2024-07-11T00:50:18.895800+00:00
FROM ruby:3.2.4-slim-bullseye as ruby
FROM demisto/python3-deb:3.11.9.103065

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
&& apt-get upgrade -y