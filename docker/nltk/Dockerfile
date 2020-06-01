
FROM demisto/python3:3.8.3.8715

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir /usr/local/share/nltk_data \
  && chmod 755 /usr/local/share/nltk_data \
  && python -m nltk.downloader -d /usr/local/share/nltk_data punkt
