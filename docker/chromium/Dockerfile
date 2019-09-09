FROM demisto/python3-deb:3.7.4.1502

COPY requirements.txt .
COPY google-chrome-stable_current_amd64.deb .
# RUN wget https://dl.google.co/linux/direct/google-chrome-stable_current_amd64.deb

RUN apt-get update && apt-get install -y --no-install-recommends \
  python-dev \
  wget \
  libxss1 \
  libappindicator1 \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

# Install Chrome
RUN apt-get update && dpkg -i google-chrome*.deb; \
apt --fix-broken -y install; \
apt-get -y install unzip \
&& rm -f google-chrome*.deb \
&& python3 -c "from webdriver_manager.chrome import ChromeDriverManager; ChromeDriverManager().install()" \
&& rm -rf /var/lib/apt/lists/*
