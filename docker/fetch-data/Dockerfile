
FROM demisto/python3:3.9.4.18682

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
  && apk add --no-cache libstdc++  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies


RUN python -m nltk.downloader punkt -d /usr/share/nltk_data


COPY ./glove_50_top_20k.p /var/glove_50_top_20k.p

COPY ./glove_100_top_20k.p /var/glove_100_top_20k.p

COPY ./fasttext_top_20k.p /var/fasttext_top_20k.p

COPY ./domain_to_rank.p /var/domain_to_rank.p

COPY ./word_to_ngram.p /var/word_to_ngram.p

COPY ./word_to_regex.p /var/word_to_regex.p
