# Last modified: 2024-07-04T16:37:39.749413+00:00
FROM demisto/python3-ubi:3.10.8.101081

COPY requirements.txt .

RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git && \
        pip install --no-cache-dir -r requirements.txt && \
        dnf remove -y python3-devel gcc gcc-c++ make wget git platform-python-pip && \
        dnf clean all && \
        rm -rf /var/cache/dnf

