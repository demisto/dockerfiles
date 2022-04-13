
FROM demisto/python3-deb:3.10.4.28391

COPY requirements.txt .

# RUN apk --update add --no-cache libmagic
RUN apt-get update && apt-get install -y --no-install-recommends && apt-get -y install libmagic1

# RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#   && pip install --no-cache-dir -r requirements.txt \
#   && apk del .build-dependencies

RUN apt-get update && apt-get install -y --no-install-recommends \
  python3-dev \
  wget \
  git \
  libemail-outlook-message-perl \ 
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
