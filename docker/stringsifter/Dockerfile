FROM demisto/python3-deb:3.10.5.31873

COPY poetry.lock .
COPY pyproject.toml .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev make gcc g++ wget git libgomp1 \
  &&  sudo curl -sSL https://install.python-poetry.org | python3 \
  && pip install -r requirements.txt \
  && apt-get purge -y --auto-remove gcc g++ make python3-dev

