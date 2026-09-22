# Last modified: 2026-09-17T05:01:17.099150+00:00

FROM demisto/crypto:1.0.0.12833174

COPY requirements.txt .

# The lxml wheel statically links its own libxml2/libxslt, so the system
# copies are not needed at runtime and only add an outdated parser to the image.
RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
