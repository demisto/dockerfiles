
FROM demisto/python3-deb:3.8.2.6981

COPY requirements.txt .
COPY odbcinst.ini /etc/odbcinst.ini

RUN apt-get update && apt-get install -y --no-install-recommends \
  unixodbc \
  freetds-bin \
  tdsodbc \
  libpq5 \
  libaio1 \
  wget \
  unzip \
&& rm -rf /var/lib/apt/lists/*

# install oracle instant client
RUN mkdir -p /opt/oracle && \
  cd /opt/oracle && \
  wget -q https://download.oracle.com/otn_software/linux/instantclient/19600/instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  unzip instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  rm instantclient-basiclite-linux.x64-19.6.0.0.0dbru.zip && \
  echo /opt/oracle/instantclient_19_6 > /etc/ld.so.conf.d/oracle-instantclient.conf && \
  ldconfig
  

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  g++ \
  libc-dev \
  libffi-dev \
  python-dev \
  unixodbc-dev \
  freetds-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  g++ \
  libc-dev \
  libffi-dev \
  python-dev \
  unixodbc-dev \
  freetds-dev \
&& rm -rf /var/lib/apt/lists/*
