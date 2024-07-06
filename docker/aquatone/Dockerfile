# Last modified: 2024-07-06T04:34:41.158767+00:00
FROM demisto/python3-deb:3.10.14.101214

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
&& rm -rf /var/lib/apt/lists/*