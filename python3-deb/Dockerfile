FROM python:3.7.1-slim-stretch

# Basic linux utilities
RUN apt-get update \
  && apt-get install -y \
    procps

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
