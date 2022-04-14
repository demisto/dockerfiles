FROM demisto/python3-deb:3.10.4.27798

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends poppler python3-dev make gcc g++ && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get purge -y --auto-remove python3-dev make gcc g++