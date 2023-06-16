
FROM demisto/python3-deb:3.10.12.63475

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full \
  && rm -rf /var/lib/apt/lists/*

# installs unrar requires non-free repo
RUN sed -i.org 's/bullseye[^ ]* main$/& contrib non-free/g' /etc/apt/sources.list \
  && apt-get update && apt-get install -y --no-install-recommends unrar \
  && rm -rf /var/lib/apt/lists/*
