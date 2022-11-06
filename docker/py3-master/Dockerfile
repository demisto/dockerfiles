
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



# handles dxl + crypto + oauthlib + py3ews + readpdf + iputils + bs4-py3 + pcap-http-extractor + unzip + parse-emails + docxpy + netutils + ssdeep + sklearn + pandas
# 73-76 - sklearn image config
# 77-80 - nltk image configuration
# 82-84 - install all os libraries needed for the images above
# 86 - install rust
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
    libxml2-dev poppler-utils iputils-ping p7zip-full p7zip-rar unrar-free libmagic-dev bind9 ssdeep g++ openssh-server less htop make rsync  \
    libpng-dev libfreetype-dev liblapack-dev gfortran musl-dev libopenblas-dev libopenblas-base libgomp1 libgpgme11 libreoffice default-jre-headless \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
    && curl https://sh.rustup.rs -sSf | bash -s -- -y \
    && apt-get purge -y --auto-remove python3-dev build-essential zlib1g-dev curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /root/.cargo \
    && pip uninstall -y pcodedmp
