FROM demisto/python3-deb:3.12.11.4801753

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Installs p7zip-full for general archive extraction.
RUN apt-get update && apt-get install -y --no-install-recommends p7zip-full \
  && rm -rf /var/lib/apt/lists/*

# The unrar-nonfree package was renamed to unrar in Debian Bookworm.
# This section adds the non-free repository and installs the correct package.
RUN sed -i.org 's/bookworm[^ ]* main$/& contrib non-free/g' /etc/apt/sources.list \
  && apt-get update \
  && apt-get install -y --no-install-recommends unrar \
  && rm -rf /var/lib/apt/lists/*