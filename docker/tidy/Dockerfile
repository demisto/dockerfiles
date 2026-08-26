# Last modified: 2026-08-24T12:13:08.304497+00:00

FROM demisto/crypto:1.0.0.11658507

COPY requirements.txt .
COPY ansible /home/demisto/ansible
COPY ansible.cfg /etc/ansible/ansible.cfg


RUN apk --update add --no-cache --virtual .build-dependencies \
    musl-dev libffi-dev openssl-dev build-base \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-dependencies
RUN apk --update add --no-cache openssl ca-certificates sshpass rsync

# This line can be removed once upgrading base image to alpine3.24
RUN echo "https://dl-cdn.alpinelinux.org/alpine/edge/main" >> /etc/apk/repositories \
  && apk --update add --no-cache --upgrade \
  "openssh-client>=10.4"

RUN ansible-galaxy install -c elliotweiser.osx-command-line-tools
RUN ansible-galaxy collection install -c geerlingguy.mac
RUN ansible-galaxy install -c ctorgalson.oh-my-zsh,v2.2.2
