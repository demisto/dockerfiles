FROM demisto/python3-deb:3.10.5.31873

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev make gcc g++ wget git libgomp1 \
  && pip install stringsifter \
  && apt-get purge -y --auto-remove gcc g++ make python3-dev wget git libgomp1

