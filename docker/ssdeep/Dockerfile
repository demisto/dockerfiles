FROM demisto/crypto:1.0.0.23151

COPY requirements.txt .

# Crypto  needs the latest pip
RUN pip3 install --no-cache-dir --upgrade pip

RUN apk --update add --no-cache --virtual \
  libfuzzy-dev \
  && pip install --no-cache-dir -r requirements.txt