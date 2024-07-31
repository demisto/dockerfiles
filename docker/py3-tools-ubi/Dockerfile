# Last modified: 2024-07-18T00:00:00.000000+00:00
FROM demisto/py3-tools-ubi:1.0.0.105970

COPY requirements.txt .

RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git && \
        pip install --no-cache-dir -r requirements.txt && \
        dnf remove -y python3-devel gcc gcc-c++ make wget git platform-python-pip && \
        dnf clean all && \
        rm -rf /var/cache/dnf

