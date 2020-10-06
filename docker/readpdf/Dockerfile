
FROM demisto/python3:3.8.5.10455

# COPY requirements1.txt .

# RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  && pip install --no-cache-dir -r requirements1.txt \
#  && apk del .build-dependencies

RUN apk --update add --no-cache \
	poppler-utils


