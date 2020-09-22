
<<<<<<< HEAD
FROM demisto/python3:3.8.6.12176
=======
FROM demisto/python3:3.8.5.10845
>>>>>>> 332562da (create argus-toolbelt docker image)

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
