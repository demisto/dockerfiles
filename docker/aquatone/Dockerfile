# Last modified: 2023-06-08T00:50:58.497489+00:00
FROM demisto/python3-deb:3.10.12.62632

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