
FROM demisto/python3:3.7.4.1150

COPY requirements.txt .

RUN apk --update add --no-cache libffi

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  libffi-dev \
  dpkg-dev dpkg \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

#Install latest patches
RUN apt-get update && apt-get install -y && apt-get install -y wget

# Install Chrome
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN dpkg -i google-chrome-stable_current_amd64.deb; apt-get -fy install