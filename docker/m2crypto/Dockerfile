# Last modified: 2026-02-02T12:39:34.255601+00:00
FROM demisto/python3:3.12.12.6947692 AS base

RUN apk --update add --no-cache swig

RUN apk --update add --no-cache --virtual .build-dependencies gcc g++ \
  musl-dev python3-dev libffi-dev openssl-dev build-base wget git

FROM base AS requirements_gen
COPY Pipfile .
COPY Pipfile.lock .
RUN pip install pipenv && pipenv install --deploy && PIPENV_YES=yes pipenv run pip freeze > /requirements.txt

FROM base
COPY --from=requirements_gen ./requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
