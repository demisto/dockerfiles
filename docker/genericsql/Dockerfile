
FROM demisto/python3-deb:3.8.6.12176

COPY requirements.txt .
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
