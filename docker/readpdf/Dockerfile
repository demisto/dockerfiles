
FROM demisto/python3:3.8.6.12176

# COPY requirements.txt .

# RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies

RUN apk --update add --no-cache \
	poppler-utils


