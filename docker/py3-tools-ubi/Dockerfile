# This is a py-tools image that is based on debian linux
FROM devdemisto/python3-ubi:3.10.8.37476

COPY requirements.txt .

RUN dnf upgrade -y --nodocs && \
    dnf install -y gcc && \
    pip install --no-cache-dir -r requirements.txt && \
    dnf remove -y gcc && \
    dnf clean all && \
    rm -rf /var/cache/dnf && \
    pip uninstall -y pcodedmp
