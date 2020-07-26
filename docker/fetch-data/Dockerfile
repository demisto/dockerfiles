
FROM demisto/python3:3.8.3.9324

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git  g++ \
  && apk add --no-cache python3-dev libstdc++  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


RUN python -m nltk.downloader punkt -d /usr/share/nltk_data


COPY ./glove_top_20k.p /var/glove_top_20k.p
