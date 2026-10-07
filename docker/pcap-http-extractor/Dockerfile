# Last modified: 2026-10-07T05:01:16.001413+00:00

FROM demisto/python3-deb:3.12.14.13495286

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  dpkg \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  tshark \
&& rm -rf /var/lib/apt/lists/*

# Do not add entries here - this is a workaround used to prevent the wireshark package from being installed in the final image
RUN for pkg in wireshark-common libwireshark18 libwireshark-data libwiretap15 libwsutil16 tshark; do \
  sed -i "/^Package: ${pkg}$/,/^$/d" /var/lib/dpkg/status; \
  rm -f /var/lib/dpkg/info/${pkg}.*; \
done
