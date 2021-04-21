
FROM demisto/python3:3.9.4.18682

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
  && apk add --no-cache libstdc++  \
  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN mkdir /ml
RUN python -c "import nltk; nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt',download_dir='/ml/nltk_data')"
ENV NLTK_DATA='/ml/nltk_data'

COPY ./glove_50_top_20k.p /ml/glove_50_top_20k.p
COPY ./glove_100_top_20k.p /ml/glove_100_top_20k.p
COPY ./fasttext_top_20k.p /ml/fasttext_top_20k.p
COPY ./domain_to_rank.p /ml/domain_to_rank.p
COPY ./word_to_ngram.p /ml/word_to_ngram.p
COPY ./word_to_regex.p /ml/word_to_regex.p

RUN chown -R demisto:demisto /ml && chmod -R 775 /ml
