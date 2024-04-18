FROM demisto/powershell-deb:7.3.0.49844


COPY requirements.txt .

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
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
    libkrb5-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
  build-essential \
  git \
  wget \
  libffi-dev \
  wget \
  libxml2-dev \
  libssl-dev \
  libkrb5-dev \
&& rm -rf /var/lib/apt/lists/*