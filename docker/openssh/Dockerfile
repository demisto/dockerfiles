
FROM demisto/python3:3.8.3.8715

# No python deps for now
# COPY requirements.txt .

# RUN apk --update add --no-cache --virtual .build-dependencies python-dev build-base wget git \
#  && pip install --no-cache-dir -r requirements.txt \
#  && apk del .build-dependencies

RUN apk --update add --no-cache openssh-client

