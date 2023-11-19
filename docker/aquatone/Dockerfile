# Last modified: 2023-11-19T08:34:30.556445+00:00
FROM demisto/python3-deb:3.10.13.78961

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