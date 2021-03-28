
FROM demisto/python3-deb:3.9.2.17957

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends python3-dev g++\
&& pip install --no-cache --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  g++ \
  python3-dev
RUN rm -rf /var/lib/apt/lists/*




