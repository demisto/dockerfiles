
FROM demisto/python3:3.8.5.10455

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3 build-base wget git
RUN pip install --no-cache-dir -r requirements.txt
RUN apk del .build-dependencies
