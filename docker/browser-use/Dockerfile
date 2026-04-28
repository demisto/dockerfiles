FROM demisto/chromium:145.0.7632.7274801

COPY requirements.txt .

# The base image already ships:
#   * Python 3.12 (from demisto/python3-deb)
#   * google-chrome-stable + chromedriver
#   * every shared library Chromium needs (libnss3, libgtk-3-0, fonts, ...)
#
# We only need to add the Python deps for the browser-use integration.
# A handful of wheels (grpcio, cffi, cryptography, ...) may need to compile
# from source, so we install python3-dev / build-essential, install, then
# purge them again to keep the image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3-dev \
      build-essential \
  && pip3 install --no-cache-dir -r requirements.txt \
  && apt-get purge -y --auto-remove \
      python3-dev \
      build-essential \
  && rm -rf /var/lib/apt/lists/*

# Tell Playwright NOT to download its own Chromium - reuse the
# google-chrome-stable binary that the base image installed.
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/opt/google/chrome/google-chrome \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
