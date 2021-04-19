
FROM demisto/python-deb:2.7.18.18420

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends --allow-downgrades \
  gcc \
  python2-dev \
  libcom-err2=1.44.5-1+deb10u3 \
  comerr-dev \
  krb5-multidev \
  libkrb5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python2-dev \
&& rm -rf /var/lib/apt/lists/*