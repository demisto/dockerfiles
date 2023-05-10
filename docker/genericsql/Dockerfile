
FROM demisto/python3-deb:3.10.11.57265

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

# Copy kerberos configuration files from host
COPY krb5.con[f] /etc/krb5.conf
COPY $USER.keyta[b] /etc/$USER.keytab