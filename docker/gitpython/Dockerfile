
FROM demisto/python3:3.8.6.13358

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies

RUN apk add --no-cache git \
  && apk add --no-cache openssh \
  && eval `ssh-agent -s` \
  && mkdir ~/.ssh \
  && echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config \
  && chmod go-w ~ \
  && chmod 700 ~/.ssh \
