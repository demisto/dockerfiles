
<<<<<<< HEAD
<<<<<<< HEAD
FROM demisto/python3:3.8.6.12176
=======
FROM demisto/python3:3.8.5.10845
>>>>>>> 332562da (create argus-toolbelt docker image)
=======
FROM demisto/python3:3.8.5.10845
>>>>>>> b52bed2d7eac819f0a7621a786148feec820f0df

COPY requirements.txt .
COPY .argus_cli.yaml /root/

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
