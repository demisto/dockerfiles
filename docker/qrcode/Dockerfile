# Last modified: 2026-07-21T09:20:28.296998+00:00

# XSUP-72883: source a FIPS provider (fips.so) from UBI9. Debian's OpenSSL 3.0
# ships no FIPS provider, so cv2/pyzbar abort on FIPS hosts.
FROM registry.access.redhat.com/ubi9:9.4 AS fips-src

FROM demisto/opencv:1.0.0.11195141

COPY Pipfile.lock .
COPY Pipfile .

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

# XSUP-72883: fipsinstall writes fipsmodule.cnf (with the MAC); activate both the
# default and fips providers so non-FIPS usage is unaffected and FIPS hosts work.
COPY --from=fips-src /usr/lib64/ossl-modules/fips.so /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
RUN openssl fipsinstall \
      -out /usr/lib/ssl/fipsmodule.cnf \
      -module /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so \
  && printf '\n.include /usr/lib/ssl/fipsmodule.cnf\n' >> /etc/ssl/openssl.cnf \
  && sed -i \
      -e 's/^# providers = provider_sect/providers = provider_sect/' \
      -e 's/^\[openssl_init\]/[openssl_init]\nproviders = provider_sect/' \
      /etc/ssl/openssl.cnf \
  && printf '[provider_sect]\nfips = fips_sect\ndefault = default_sect\n[default_sect]\nactivate = 1\n' >> /etc/ssl/openssl.cnf \
  && openssl list -providers >/dev/null
