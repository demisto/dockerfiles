FROM node:18.9.0-bullseye-slim

WORKDIR /content

# Install node modules for readme validation in demisto-sdk validate
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json /content/

RUN apt-get update && apt-get install -y curl && npm ci
