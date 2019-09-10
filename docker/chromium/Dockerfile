FROM demisto/python3-deb:3.7.4.1163

COPY requirements.txt .
COPY google-chrome-stable_current_amd64.deb .
COPY chromedriver_linux64.zip .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python-dev \
  wget \
  libxss1 \
  libappindicator1 \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

# Installing Google Chrome 76.0.3809.100 and ChromeDriver 76.0.3809.126
RUN apt-get update && dpkg -i google-chrome*.deb; \
apt --fix-broken -y install; \
apt-get -y install unzip \
&& unzip chromedriver_mac64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf /var/lib/apt/lists/* google-chrome*.deb chromedriver_linux64.zip \
&& google-chrome --version \
&& chromedriver --version
