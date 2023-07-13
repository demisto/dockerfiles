FROM demisto/python3-deb:3.10.5.31873

COPY pyproject.toml .
COPY poetry.lock .

RUN apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends curl python3-dev make gcc g++ wget git libgomp1 \
  && curl -sSL https://install.python-poetry.org | python3 - \
  && poetry install --no-interaction \
  && curl -sSL https://raw.githubusercontent.com/sdispater/poetry/master/get-poetry.py | python - --uninstall \
  && rm -rf /root/.cache/pypoetry && apt-get purge -y --auto-remove gcc g++ make python3-dev curl

