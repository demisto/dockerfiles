
# TODO - update the image here
FROM devdemisto/py3-tools-deb:1.0.0.36944

COPY requirements.txt .


# chromium
#RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev wget libxss1 poppler-utils fonts-noto-cjk fonts-noto-core zlib1g-dev \
#&& wget http://http.us.debian.org/debian/pool/main/liba/libappindicator/libappindicator1_0.4.92-7_amd64.deb -O /tmp/libappindicator1_0.4.92-7_amd64.deb \
#&& wget http://http.us.debian.org/debian/pool/main/libi/libindicator/libindicator7_0.5.0-4_amd64.deb -O /tmp/libindicator7_0.5.0-4_amd64.deb \
#&& apt-get install -y  /tmp/libindicator7_0.5.0-4_amd64.deb /tmp/libappindicator1_0.4.92-7_amd64.deb \
#&& pip3 install --no-cache-dir -r requirements.txt \
#&& apt-get purge -y --auto-remove \
#  python3-dev \
#  zlib1g-dev \
#&& rm -rf /var/lib/apt/lists/*
#
## Based on instructions at: https://tecadmin.net/setup-selenium-with-chromedriver-on-debian/
## Will install the latest version available from the chrome repo.
## To see available chromedriver go to https://chromedriver.storage.googleapis.com/ and search for the major version
## of chrome(for  example 91.0).
#
#COPY download_chromedriver.sh .
#
## Deps needed by google-chrome
#RUN apt-get update && apt-get -t bullseye-backports install -y --no-install-recommends \
#  gnupg1 \
#  libgtk-3-0 \
#  libu2f-udev \
#  udev \
#&& apt-get update && apt-get install -y --no-install-recommends \
#  curl \
#  unzip \
#&& curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
#&& echo "deb [arch=amd64]  http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
#&& apt-get -y update && apt-get install -y google-chrome-stable \
#&& apt-get install -y tigervnc-standalone-server x11-utils imagemagick \
#&& ./download_chromedriver.sh \
#&& unzip chromedriver_linux64.zip \
#&& mv chromedriver /usr/bin/chromedriver \
#&& rm -rf chromedriver_linux64.zip \
#&& google-chrome --version \
#&& chromedriver --version \
#&& apt-get purge -y --auto-remove \
#  curl \
#  unzip \
#&& rm -rf /var/lib/apt/lists/*
#
#ENV CHROME_EXE="/opt/google/chrome/google-chrome"
#
#
## tesseract
#RUN apt-get update && apt-get upgrade -y && apt-get -t bullseye-backports install gcc g++ git pkg-config \
#make autoconf automake libtool libpng-dev libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev liblept5 -y \
#&& mkdir /build && cd /build && git clone --depth 1 https://github.com/tesseract-ocr/tesseract.git \
#&& cd tesseract && ./autogen.sh && ./configure && gmake && make install && ldconfig \
#&& apt-get -t bullseye-backports install -y --no-install-recommends imagemagick file \
#&& apt-get purge -y --auto-remove gcc g++ pkg-config make autoconf automake libtool libpng-dev \
#libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev \
#&& rm -rf /var/lib/apt/lists/* \
#&& git clone https://github.com/zdenop/tessdata_downloader.git \
#&& cd tessdata_downloader \
#&& for lang in  eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
#do python tessdata_downloader.py -o /usr/local/share/tessdata/ -l $lang; done \
#&& rm -rf /build \
#&& tesseract --version --list-langs



# dxl + crypto + oauthlib + py3ews + readpdf + iputils + bs4-py3 + pcap-http-extractor + unzip + parse-emails + docxpy + netutils + ssdeep + sklearn + pandas
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev build-essential libstd-rust cargo libxml2-dev poppler-utils inetutils-ping p7zip libmagic-dev bind9 ssdeep g++ openssh-server less htop make rsync libpng-dev libfreetype-dev liblapack-dev gfortran musl-dev libopenblas-dev libopenblas-base libgomp1 \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove python3-dev build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /root/.cargo


# sklearn config
RUN mkdir /ml
RUN python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')"

ENV NLTK_DATA='/ml/nltk_data'
RUN chown -R demisto:demisto /ml && chmod -R 775 /ml


# nltk
RUN mkdir /usr/local/share/nltk_data \
  && chmod 755 /usr/local/share/nltk_data \
  && python -m nltk.downloader -d /usr/local/share/nltk_data punkt

# office-utils
RUN mkdir -p /usr/share/man/man1 \
&& apt-get update && apt-get install -y --no-install-recommends \
  libgpgme11 \
  libreoffice \
  default-jre-headless \
&& rm -rf /var/lib/apt/lists/* \


# dxl
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  libffi-dev openssl-dev \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies


# crypto
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  rust cargo \
#  libffi-dev openssl-dev \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies \
#  && rm -rf /root/.cargo \


# oauthlib
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  libffi-dev openssl-dev \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies


# powershell-deb

#FROM mcr.microsoft.com/powershell:7.2.2-debian-buster-slim-20220318
#
#RUN echo 'deb http://deb.debian.org/debian buster-backports main' >> /etc/apt/sources.list
#
## Basic linux utilities
#RUN apt-get update && apt-get install -y --no-install-recommends \
#  procps \
#&& rm -rf /var/lib/apt/lists/*
#
## Upgrade all packages to latest
#RUN apt-get update && apt-get -y --no-install-recommends upgrade \
#&& rm -rf /var/lib/apt/lists/*
#
## Upgrade using backports
#RUN apt-get update && apt-get -t buster-backports -y --no-install-recommends upgrade \
#&& rm -rf /var/lib/apt/lists/*
#
#RUN groupadd --gid 4000 demisto \
#  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto

# py3ews
#RUN apk --update add --no-cache libxslt-dev \
#  && apk --update add --no-cache --virtual .build-dependencies python3-dev gcc build-base wget git libffi-dev openssl-dev python3-dev libxml2-dev \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies

# taxii
#RUN apk add --update --no-cache libxslt libxml2





# sklearn
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git g++ python3-dev\
#        openssh curl ca-certificates openssl less htop \
#		make  rsync \
#        libpng-dev freetype-dev libexecinfo-dev lapack-dev \
#        gfortran \
#        musl-dev openblas-dev\
#  && apk add --no-cache libstdc++  \
#  && apk add --no-cache  openblas libgomp \
#  && apk add --no-cache bash  \
#  && ln -s /usr/include/locale.h /usr/include/xlocale.h \
#  && pip3 install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies
#
#RUN mkdir /ml
#RUN python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')"
#
#ENV NLTK_DATA='/ml/nltk_data'
#RUN chown -R demisto:demisto /ml && chmod -R 775 /ml


# readpdf
#RUN apt-get update && apt-get install -y --no-install-recommends poppler-utils python3-dev make gcc g++ && \
#    pip install --no-cache-dir -r requirements.txt && \
#    apt-get purge -y --auto-remove python3-dev make gcc g++ && \
#    rm -rf /var/lib/apt/lists/*

## nltk
#RUN mkdir /usr/local/share/nltk_data \
#  && chmod 755 /usr/local/share/nltk_data \
#  && python -m nltk.downloader -d /usr/local/share/nltk_data punkt


# iputils
#RUN apk --update add --no-cache iputils

# bs4-py3
#RUN apk --update add --no-cache --virtual .build-dependencies  python3-dev libxml2-dev libxslt-dev build-base wget git \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies


# pcap-http-extractor
#RUN apt-get update && apt-get install -y --no-install-recommends \
#  gcc \
#  python-dev \
#&& pip install --no-cache-dir -r requirements.txt \
#&& apt-get purge -y --auto-remove \
#  gcc \
#  python-dev \
#&& rm -rf /var/lib/apt/lists/*
#
#RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
#  tshark \
#&& rm -rf /var/lib/apt/lists/*


# unzip
#RUN apk --update add --no-cache p7zip
## installs unrar
#RUN apk --update add --no-cache unrar


# parse-emails
#RUN apk --update add --no-cache libmagic
#
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base libffi-dev wget git \
#  && pip install --no-cache-dir -r requirements.txt \
#  && pip uninstall -y pcodedmp \
#  && apk del .build-dependencies

# office-utils
#RUN apt-get update && apt-get install -y --no-install-recommends \
#  gcc \
#  python3-dev \
#&& pip install --no-cache-dir -r requirements.txt \
#&& apt-get purge -y --auto-remove \
#  gcc \
#  python-dev \
#&& rm -rf /var/lib/apt/lists/*
#
#RUN mkdir -p /usr/share/man/man1 \
#&& apt-get update && apt-get install -y --no-install-recommends \
#  libgpgme11 \
#  libreoffice \
#  default-jre-headless \
#&& rm -rf /var/lib/apt/lists/*


# docxpy
#RUN apk --update add --no-cache libxml2 libxslt
#
#RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget libxml2-dev libxslt-dev \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies

# pandas
#RUN apk add --no-cache libstdc++ \
#  && apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies

# netutils
#RUN apk --update add --no-cache curl bind-tools


# ssdeep
#RUN apt-get update && apt-get install ssdeep \
#    && rm -rf /var/lib/apt/lists/* \


# feed-performence-test
#FROM demisto/faker3:1.0.0.4979 AS build
#RUN mkdir -p /perf
#COPY script.py /perf
#
#WORKDIR /perf
#RUN python -u script.py
#
#FROM demisto/python3:3.9.6.24019
#RUN mkdir -p /perf
#WORKDIR /perf
#COPY --from=build /perf/ips.csv .
#COPY --from=build /perf/domains.csv .
#COPY --from=build /perf/hashes.csv .
