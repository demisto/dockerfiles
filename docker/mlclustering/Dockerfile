FROM demisto/python3-9-deb:3.9.16.103780

COPY pyproject.toml .
COPY poetry.lock .

RUN apt-get update \
&& apt-get install -y --no-install-recommends \
  gfortran wget git autoconf libtool automake g++ pkg-config libhdf5-dev cmake
RUN pip install --upgrade setuptools && pip install poetry && poetry config --local installer.no-binary :all: \
&& poetry config virtualenvs.create false  \
&& poetry install --no-root \
&& apt-get purge -y --auto-remove  \
  gfortran wget git autoconf libtool automake g++ pkg-config libhdf5-dev cmake
