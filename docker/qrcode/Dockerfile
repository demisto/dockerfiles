FROM demisto/opencv:1.0.0.11195141

COPY Pipfile.lock .
COPY Pipfile .

# libzbar0: pyzbar runtime dep (build tools removed afterwards).
RUN apt-get update && apt-get -t bookworm-backports install -y --no-install-recommends \
  gcc \
  python3-dev \
  libzbar0 \
  build-essential \
  && pip install --no-cache-dir pipenv \
  && pipenv install --system --deploy \
  && apt-get purge -y --auto-remove \
    gcc \
    python3-dev \
    build-essential \
  && rm -rf /var/lib/apt/lists/* \
  && pip uninstall -y pipenv

# XSUP-72883: opencv 5.x bundles a RedHat OpenSSL 1.1.1k that crashes the FIPS
# self-test. Pin cv2 to 4.11.0.86 (bundles vanilla libssl.so.1.1) to fix FIPS.
RUN pip install --no-cache-dir "opencv-contrib-python==4.11.0.86"
