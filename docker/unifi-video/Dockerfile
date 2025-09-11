FROM demisto/opencv:1.0.0.4757640

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# --- Mitigate CVE-2025-6965: Install SQLite 3.50.2+ from source ---
RUN apt-get update && apt-get install -y wget make gcc libreadline-dev zlib1g-dev \
  && wget https://www.sqlite.org/2024/sqlite-autoconf-3500200.tar.gz \
  && tar xzf sqlite-autoconf-3500200.tar.gz \
  && cd sqlite-autoconf-3500200 \
  && ./configure && make && make install \
  && cd .. && rm -rf sqlite-autoconf-3500200* \
  && ldconfig

# --- Mitigate CVE-2023-31484: Upgrade CPAN.pm to >=2.35 ---
RUN apt-get update && apt-get install -y perl cpanminus \
  && cpan App::cpanminus \
  && cpanm CPAN \
  && rm -rf /var/lib/apt/lists/*
