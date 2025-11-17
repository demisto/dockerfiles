# Last modified: 2025-11-05T04:37:32.106034+00:00

# Part of IOT - XSOAR integration project. 
# See docs at: https://docs.paloaltonetworks.com/iot/iot-security-integration/get-started-with-iot-security-integrations/third-party-integrations-using-on-premises-xsoar#id99b6436d-38d5-464d-9f8f-87bc84d6b628
FROM demisto/python3-deb:3.12.12.5735221

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends python3-dev wget git gcc g++ make cmake \
  && pip install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
  gcc \
  g++ \
  make \
  cmake \
  python3-dev \
  wget \
  git \
&& rm -rf /var/lib/apt/lists/*
