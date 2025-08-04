
FROM demisto/m2crypto:1.0.0.2486791

# Upgrade all packages to latest
RUN apk --update --no-cache upgrade

COPY requirements.txt .

# after updating the m2crypto tag from 1.0.0.2486791 - we can renove the line && pip install --upgrade setuptools \
RUN apk --update add --no-cache --virtual .build-dependencies build-base linux-headers \
    python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && pip install --upgrade setuptools \
  && apk del .build-dependencies
