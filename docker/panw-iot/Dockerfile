# Part of IOT - XSOAR integration project. 
# See docs at: https://docs.paloaltonetworks.com/iot/iot-security-integration/get-started-with-iot-security-integrations/third-party-integrations-using-on-premises-xsoar#id99b6436d-38d5-464d-9f8f-87bc84d6b628
FROM demisto/python3:3.10.12.63474

COPY requirements.txt .

RUN apk --update add --no-cache --virtual .build-dependencies python3-dev build-base wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apk del .build-dependencies
