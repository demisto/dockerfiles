
# TODO - update the image here
FROM devdemisto/py3-tools-deb:1.0.0.37132

COPY requirements.txt .


# chromium
RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev wget libxss1 poppler-utils fonts-noto-cjk fonts-noto-core zlib1g-dev \
&& wget http://http.us.debian.org/debian/pool/main/liba/libappindicator/libappindicator1_0.4.92-7_amd64.deb -O /tmp/libappindicator1_0.4.92-7_amd64.deb \
&& wget http://http.us.debian.org/debian/pool/main/libi/libindicator/libindicator7_0.5.0-4_amd64.deb -O /tmp/libindicator7_0.5.0-4_amd64.deb \
&& apt-get install -y  /tmp/libindicator7_0.5.0-4_amd64.deb /tmp/libappindicator1_0.4.92-7_amd64.deb \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
  zlib1g-dev \
&& rm -rf /var/lib/apt/lists/*

# Based on instructions at: https://tecadmin.net/setup-selenium-with-chromedriver-on-debian/
# Will install the latest version available from the chrome repo.
# To see available chromedriver go to https://chromedriver.storage.googleapis.com/ and search for the major version
# of chrome(for  example 91.0).

COPY download_chromedriver.sh .

# Deps needed by google-chrome
RUN apt-get update && apt-get -t bullseye-backports install -y --no-install-recommends gnupg1 libgtk-3-0 libu2f-udev udev \
    && apt-get update && apt-get install -y --no-install-recommends \
      curl \
      unzip \
    && curl -sS -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64]  http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get -y update && apt-get install -y google-chrome-stable \
    && apt-get install -y tigervnc-standalone-server x11-utils imagemagick \
    && ./download_chromedriver.sh \
    && unzip chromedriver_linux64.zip \
    && mv chromedriver /usr/bin/chromedriver \
    && rm -rf chromedriver_linux64.zip \
    && google-chrome --version \
    && chromedriver --version \
    && apt-get purge -y --auto-remove \
      curl \
      unzip \
    && rm -rf /var/lib/apt/lists/*

ENV CHROME_EXE="/opt/google/chrome/google-chrome"


# tesseract
RUN apt-get update && apt-get upgrade -y && apt-get -t bullseye-backports install gcc g++ git pkg-config \
    make autoconf automake libtool libpng-dev libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev liblept5 -y \
    && mkdir /build && cd /build && git clone --depth 1 https://github.com/tesseract-ocr/tesseract.git \
    && cd tesseract && ./autogen.sh && ./configure && gmake && make install && ldconfig \
    && apt-get -t bullseye-backports install -y --no-install-recommends imagemagick file \
    && apt-get purge -y --auto-remove gcc g++ pkg-config make autoconf automake libtool libpng-dev \
    libjpeg-dev libtiff5-dev zlib1g-dev libleptonica-dev libicu-dev libpango1.0-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/zdenop/tessdata_downloader.git \
    && cd tessdata_downloader \
    && for lang in  eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
    do python tessdata_downloader.py -o /usr/local/share/tessdata/ -l $lang; done \
    && rm -rf /build \
    && tesseract --version --list-langs



# genericsql
COPY odbcinst.ini /etc/odbcinst.ini

RUN apt-get update && apt-get install -y --no-install-recommends \
  unixodbc \
  freetds-bin \
  libpq5 \
  libaio1 \
  wget \
  unzip \
  libssl1.1 \
&& rm -rf /var/lib/apt/lists/*

# install oracle instant client
RUN mkdir -p /opt/oracle && \
  cd /opt/oracle && \
  wget -q https://download.oracle.com/otn_software/linux/instantclient/19600/instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  unzip instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  rm instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  echo /opt/oracle/instantclient_19_6 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
  ldconfig

# install freetds
RUN apt-get update && apt-get install -y --no-install-recommends \
  build-essential \
  libc-dev \
  libssl-dev \
  unixodbc-dev \
&& wget ftp://ftp.freetds.org/pub/freetds/stable/freetds-1.1.39.tar.gz \
&& tar -xzf freetds-1.1.39.tar.gz \
&& cd freetds-1.1.39 \
&& ./configure --with-openssl --with-unixodbc=/usr --enable-msdblib \
&& make \
&& make install \
&& apt-get purge -y --auto-remove \
  build-essential \
  libc-dev \
  libssl-dev \
  unixodbc-dev \
&& rm -rf /var/lib/apt/lists/* \
&& cd .. \
&& rm freetds-1.1.39.tar.gz \
&& rm -rf freetds-1.1.39

# Install the Microsoft ODBC driver for SQL Server (Linux)
RUN apt-get update \
&& apt-get install -y --allow-downgrades gpgv gnupg2 curl apt-utils \
&& curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
&& curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list \
&& apt-get update \
&& ACCEPT_EULA=Y apt-get install msodbcsql18 \
&& apt-get install -y unixodbc-dev libgssapi-krb5-2

# install python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  g++ \
  libc-dev \
  libffi-dev \
  python3-dev \
  unixodbc-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  g++ \
  libc-dev \
  libffi-dev \
  python3-dev \
  unixodbc-dev \
&& rm -rf /var/lib/apt/lists/*

# Handling the issue described here https://github.com/mkleehammer/pyodbc/issues/610#issuecomment-534920201 by using TLS v1
RUN sed -i s/DEFAULT@SECLEVEL=2/DEFAULT@SECLEVEL=1/g /etc/ssl/openssl.cnf \
  && sed -i s/TLSv1.2/TLSv1/g /etc/ssl/openssl.cnf


# populate zeep's cache so offline can work too
ENV ZEEP_STATIC_CACHE_DB=/zeep/static/cache.db
COPY zeep-add-to-cache.py .



# handles dxl + crypto + oauthlib + py3ews + readpdf + iputils + bs4-py3 + pcap-http-extractor + unzip + parse-emails + docxpy + netutils + ssdeep + sklearn + pandas + zeep + python_pancloud_v2 + ippysocks + akamai + google-k8s-engine
# 1) sklearn image config
# 2) nltk image configuration
# 3) install all os libraries needed for the images above
# 4) zeep image config
# 5) mlurlphishing config
ENV NLTK_DATA='/ml/nltk_data'
RUN pip install --no-cache-dir -r requirements.txt \
    && mkdir /ml \
    && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
    && chown -R demisto:demisto /ml && chmod -R 775 /ml \
    && mkdir /usr/local/share/nltk_data \
    && chmod 755 /usr/local/share/nltk_data \
    && python -m nltk.downloader -d /usr/local/share/nltk_data punkt \
    && mkdir -p /usr/share/man/man1 \
    && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev build-essential cargo \
    libxml2-dev poppler-utils iputils-ping p7zip-full unrar-free libmagic-dev bind9 ssdeep g++ openssh-server less htop make rsync openssl  \
    libpng-dev libffi-dev libxslt-dev libfreetype-dev liblapack-dev gfortran musl-dev libopenblas-dev libopenblas-base libgomp1 libgpgme11 libreoffice default-jre-headless \
    libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && mkdir -p /zeep/static \
    && chmod 755 /zeep \
    && chmod 755 /zeep/static \
    && python zeep-add-to-cache.py https://www.w3.org/2005/05/xmlmime \
    && python zeep-add-to-cache.py http://www.w3.org/2005/05/xmlmime \
    && mkdir /model \
    && mv model_docker.pkl /model/model_docker.pkl \
    && chmod -R 775 /model \
    && apt-get purge -y --auto-remove python3-dev build-essential zlib1g-dev curl libxrender-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /root/.cargo \
    && pip uninstall -y pcodedmp
