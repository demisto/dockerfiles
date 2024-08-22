
FROM demisto/python3-9-deb:3.9.19.107879

COPY requirements.txt .

# Install dependencies required for Python debugging
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  gdb \
  python3-dev \
  python3-pip \
  python3-setuptools \
  python3-dbg \
  libc6-dbg \
  git \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*

# Set environment variables for gdb
ENV PYTHONPATH=/usr/lib/python3.9
ENV LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libpython3.9d.so.1.0

# Add gdbinit with Python auto-load script
RUN echo "python\nimport gdb\ngdb.execute('source /usr/share/gdb/auto-load/usr/bin/python3.9m-gdb.py')\nend\n" > ~/.gdbinit
