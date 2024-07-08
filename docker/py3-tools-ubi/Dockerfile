# Last modified: 2024-06-12T16:36:42.444438+00:00
FROM devdemisto/python3-ubi:3.11.9.99273
# Last modified: 2024-07-06T04:36:22.589626+00:00
FROM demisto/python3-ubi:3.10.8.101227

COPY requirements.txt .

RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git && \
        pip install --no-cache-dir -r requirements.txt && \
        dnf remove -y python3-devel gcc gcc-c++ make wget git platform-python-pip && \
        dnf clean all && \
        rm -rf /var/cache/dnf

