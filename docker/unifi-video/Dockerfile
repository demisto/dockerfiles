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
# Fix CVE-2025-6965: Update SQLite to a patched version
RUN apt-get update && apt-get install -y --no-install-recommends sqlite3 && rm -rf /var/lib/apt/lists/*

# --- Mitigate CVE-2023-31484: Upgrade CPAN.pm to >=2.35 ---
RUN apt-get update && apt-get install -y perl cpanminus \
  && cpan App::cpanminus \
  && cpanm CPAN \
  && rm -rf /var/lib/apt/lists/*
