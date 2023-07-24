# Part of IOT - XSOAR integration project. 
# See docs at: https://docs.paloaltonetworks.com/iot/iot-security-integration/get-started-with-iot-security-integrations/third-party-integrations-using-on-premises-xsoar#id99b6436d-38d5-464d-9f8f-87bc84d6b628
FROM demisto/python3-deb:3.10.12.65454

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  wget \
  git \
&& rm -rf /var/lib/apt/lists/*
