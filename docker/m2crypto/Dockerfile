# Last modified: 2026-05-17T08:51:11.213208+00:00
FROM demisto/python3:3.12.13.9059085 AS base

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
