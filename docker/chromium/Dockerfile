FROM demisto/python3-deb:3.8.3.8347

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python-dev \
  wget \
  libxss1 \
  libappindicator1 \
  poppler-utils \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python-dev \
&& rm -rf /var/lib/apt/lists/*

# Installing Google Chrome 80.0.3987.87-1 and ChromeDriver 80.0.3987.16
# Goolge chrome download from: https://www.google.com/chrome/?platform=linux
# Chrome driver download from: https://chromedriver.chromium.org/downloads
# Make sure to download the proper versions that match.
# IMPORTANT: we use wget to avoid using copy to get a small image. If you update the zip files you must update the download links to the proper commit hash
RUN wget -q https://github.com/demisto/dockerfiles/raw/f4918f4996661cee8d420c887934a938f4a5ed6f/docker/chromium/chromedriver_linux64.zip && \
wget -q https://github.com/demisto/dockerfiles/raw/f4918f4996661cee8d420c887934a938f4a5ed6f/docker/chromium/google-chrome-stable_current_amd64.deb && \
apt-get update && apt install -y --no-install-recommends \
   ./google-chrome-stable_current_amd64.deb \
   unzip \
&& unzip chromedriver_linux64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf /var/lib/apt/lists/* google-chrome-stable_current_amd64.deb chromedriver_linux64.zip \
&& google-chrome --version \
&& chromedriver --version
