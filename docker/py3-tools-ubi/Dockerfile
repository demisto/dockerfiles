FROM devdemisto/python3-ubi:3.10.8.65160

COPY requirements.txt .

RUN microdnf install -y --nodocs python3-devel gcc gcc-c++ make wget git && \
        pip install --no-cache-dir -r requirements.txt && \
        microdnf remove -y python3-devel gcc gcc-c++ make wget platform-python-pip git perl-Git && \
        microdnf clean all && \
        rm -rf /var/cache

