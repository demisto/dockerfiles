FROM demisto/python3-deb:3.9.5.20070

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  python3-dev \
  wget \
  libxss1 \
  libappindicator1 \
  poppler-utils \
  fonts-noto-cjk \
  fonts-noto-core \
&& pip3 install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Installing Google Chrome 83.0.4103.97-1 and ChromeDriver 83.0.4103.39
# Goolge chrome download from: https://www.google.com/chrome/?platform=linux
# Chrome driver download from: https://chromedriver.chromium.org/downloads
# Make sure to download the proper versions that match.
# You can check the version of the downloaded chrome by running:
# docker run --rm -it -v `pwd`:/work -w /work  demisto/chromium:1.0.0.7857 dpkg -I docker/chromium/google-chrome-stable_current_amd64.deb | grep -i version 
# IMPORTANT: we use wget to avoid using copy to get a small image. If you update the zip files you must update the download links to the proper commit hash
RUN wget -q https://github.com/demisto/dockerfiles/raw/77664ef86c080c09ebee7ec27af6d71aa455092c/docker/chromium/chromedriver_linux64.zip && \
wget -q https://github.com/demisto/dockerfiles/raw/77664ef86c080c09ebee7ec27af6d71aa455092c/docker/chromium/google-chrome-stable_current_amd64.deb && \
apt-get update && apt install -y --no-install-recommends \
   ./google-chrome-stable_current_amd64.deb \
   unzip \
&& unzip chromedriver_linux64.zip \
&& mv chromedriver /usr/bin/chromedriver \
&& rm -rf /var/lib/apt/lists/* google-chrome-stable_current_amd64.deb chromedriver_linux64.zip \
&& google-chrome --version \
&& chromedriver --version
