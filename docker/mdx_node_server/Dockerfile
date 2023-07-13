# Last modified: 2023-07-13T12:44:51.147552
FROM node:18.9.1-bullseye-slim

ARG BRANCH_NAME=master
ARG DEMISTO_SDK_URL=https://raw.githubusercontent.com/demisto/demisto-sdk/${BRANCH_NAME}

WORKDIR /content

# Install node modules for readme validation in demisto-sdk validate
ADD ${DEMISTO_SDK_URL}/package.json /content/
ADD ${DEMISTO_SDK_URL}/package-lock.json /content/


ADD ${DEMISTO_SDK_URL}/demisto_sdk/commands/common/markdown_server/mdx-parse-server.js /content/
ADD ${DEMISTO_SDK_URL}/demisto_sdk/commands/common/markdown_server/markdownlintconfig.js /content/

RUN npm ci

CMD ["node", "mdx-parse-server.js"]
