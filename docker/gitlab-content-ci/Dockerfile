FROM demisto/python3-deb:3.9.1.14969

RUN apt-get update

RUN apt-get install -y curl jq unzip openssh-client gcc libffi-dev libssl-dev git npm zip netcat wget

RUN npm npm@6.14.6 -g n

RUN n v12.18.4 && PATH="$PATH"

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Instaling the gsutil
RUN  apt-get update -y \
  && apt-get install apt-transport-https ca-certificates gnupg=2.2.12-1+deb10u1 gpgv=2.2.12-1+deb10u1 -y --allow-downgrades\
  && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" |  tee -a /etc/apt/sources.list.d/google-cloud-sdk.list \
  && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - \
  &&  apt-get update &&  apt-get install google-cloud-sdk -y\
  && gcloud --version \
  && gsutil --version

# Currently sh is linked to dash, linking it to /bin/bash instead
RUN rm /bin/sh && ln -s /bin/bash /bin/sh

# Creating a user with home directory that matces the home directory of github actions, and give the user sudo access
#RUN groupadd --gid 1000 github && mkdir -p /github/ && useradd -m -d /github/home --uid 1000 --gid root --shell /bin/bash github
