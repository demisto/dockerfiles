# Last modified: 2022-12-19T12:44:51.147552
FROM node:18.9.1-bullseye-slim

WORKDIR /content

# Install node modules for readme validation in demisto-sdk validate
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package.json /content/
ADD https://raw.githubusercontent.com/demisto/demisto-sdk/master/package-lock.json /content/

RUN npm ci

# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
COPY openssl.cnf /etc/ssl/openssl.cnf