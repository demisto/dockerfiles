
FROM demisto/python-deb:2.7.18.56786

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python2-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python2-dev \
&& rm -rf /var/lib/apt/lists/*

# update openssl.cnf to support TLS 1.0 (old exchange servers)
RUN sed -i s/DEFAULT@SECLEVEL=2/DEFAULT@SECLEVEL=1/g /etc/ssl/openssl.cnf \
  && sed -i s/TLSv1.2/TLSv1/g /etc/ssl/openssl.cnf
