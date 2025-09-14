# Last modified: 2025-09-12T03:11:14.185937+00:00
FROM demisto/python3-deb:3.11.10.117398
# because of this issue we still using 3.11 https://github.com/mandiant/stringsifter/issues/41

COPY requirements.txt .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev  \
    make gcc g++ wget git libgomp1 \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get purge -y --auto-remove gcc g++ make python3-dev wget git
