FROM demisto/python3-deb:3.7.4.1163

COPY requirements.txt .
COPY google-chrome-stable_current_amd64.deb .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python-dev \
  wget \
&& pip3 install --no-cache-dir -r requirements.txt

# Install Chrome
#RUN wget https://dl.google.co/linux/direct/google-chrome-stable_current_amd64.deb; \
RUN dpkg -i google-chrome-stable_current_amd64.deb; \
apt-get -fy install unzip; \
apt --fix-broken -y install

# Clean Up
RUN apt-get purge -y --auto-remove \
  gcc \
  python-dev \
&& rm -rf /var/lib/apt/lists/* \
&& rm -f google-chrome*.deb;