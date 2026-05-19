FROM demisto/python3-deb:3.12.13.8857500

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

COPY Pipfile.lock .
COPY Pipfile .

#Install tools for building binary deps (will be removed later on)
RUN apt-get update && apt-get install -y -f --no-install-recommends \
    gcc \
    python3-dev \
    build-essential \
    wget \
    git \
    libxml2 \
    libxslt1.1 \
	libkrb5-3 \
    libffi-dev \
    libxml2-dev \
    libxslt-dev \
    libssl-dev \
&& apt-get install -y -f --no-install-recommends --allow-downgrades \
    libcom-err2=1.47.0-2+b2 \
    libkrb5-dev \
&& pip install --no-cache-dir pipenv \
&& pipenv install --system --deploy \
&& python3 -c 'import os; [open(os.path.join(r, f), "a").write("\norig_create = create_urllib3_context\ndef patched_create_urllib3_context(*args, **kwargs):\n    if len(args) <= 3 and not kwargs.get(\"ciphers\") and \"DEFAULT_CIPHERS\" in globals():\n        kwargs[\"ciphers\"] = globals()[\"DEFAULT_CIPHERS\"]\n    return orig_create(*args, **kwargs)\ncreate_urllib3_context = patched_create_urllib3_context\n") for r, d, fs in os.walk("/usr") for f in fs if f == "ssl_.py" and "urllib3/util" in os.path.join(r, f)]' \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  build-essential \
  git \
  wget \
  libffi-dev \
  libxml2-dev \
  libssl-dev \
  libkrb5-dev \
&& rm -rf /var/lib/apt/lists/* \
&& pip uninstall -y pipenv
