# Last modified: 2026-05-12T04:43:40.954754+00:00

FROM demisto/python3-deb:3.12.13.8927230

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  tshark \
&& rm -rf /var/lib/apt/lists/* \
&& mkdir -p /tmp/tshark-save/lib /tmp/tshark-save/bin /tmp/tshark-save/share /tmp/tshark-save/etc \
&& cp /usr/bin/tshark /usr/bin/dumpcap /usr/bin/capinfos /usr/bin/editcap /usr/bin/mergecap /usr/bin/reordercap /tmp/tshark-save/bin/ \
&& cp -a /usr/lib/x86_64-linux-gnu/libwireshark* /usr/lib/x86_64-linux-gnu/libwiretap* /usr/lib/x86_64-linux-gnu/libwsutil* /tmp/tshark-save/lib/ \
&& (cp -a /usr/lib/x86_64-linux-gnu/wireshark /tmp/tshark-save/lib/ 2>/dev/null || true) \
&& cp -a /usr/share/wireshark /tmp/tshark-save/share/ \
&& cp -a /etc/wireshark /tmp/tshark-save/etc/ \
&& (dpkg --purge --force-depends wireshark-common libwireshark16 libwireshark-data libwiretap13 libwsutil14 tshark 2>/dev/null || true) \
&& cp /tmp/tshark-save/bin/* /usr/bin/ \
&& cp -a /tmp/tshark-save/lib/libwireshark* /tmp/tshark-save/lib/libwiretap* /tmp/tshark-save/lib/libwsutil* /usr/lib/x86_64-linux-gnu/ \
&& (cp -a /tmp/tshark-save/lib/wireshark /usr/lib/x86_64-linux-gnu/ 2>/dev/null || true) \
&& mkdir -p /usr/share/wireshark && cp -a /tmp/tshark-save/share/wireshark/* /usr/share/wireshark/ \
&& mkdir -p /etc/wireshark && cp -a /tmp/tshark-save/etc/wireshark/* /etc/wireshark/ \
&& rm -rf /tmp/tshark-save \
&& ldconfig
