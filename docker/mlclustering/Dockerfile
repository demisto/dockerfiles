FROM devdemisto/python3-9-deb:3.9.16.103723

COPY pyproject.toml .
COPY poetry.lock .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev build-essential python3-dev
RUN pip install poetry && poetry export -f requirements.txt --output requirements.txt --without-hashes \
&& pip install --no-binary :all: --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
