FROM circleci/golang:1.11.5-stretch-node

RUN sudo apt-get update && sudo apt-get install -y --no-install-recommends apt-transport-https

ENV CLOUD_SDK_REPO=cloud-sdk-stretch

RUN echo "deb https://packages.cloud.google.com/apt $CLOUD_SDK_REPO main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
  curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add - && \
  sudo apt-get update && \
  sudo apt-get install -y google-cloud-sdk && \
  gcloud --version

RUN sudo npm install -g firebase-tools && \
  firebase --version

RUN go get -u golang.org/x/lint/golint
