FROM demisto/python3-deb:3.10.5.31873

COPY Pipfile Pipfile
COPY Pipfile.lock Pipfile.lock

RUN pip install pipenv

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev make gcc g++ wget git libgomp1 \
  && pipenv install --system \
  && apt-get purge -y --auto-remove gcc g++ pipenv make python3-dev

