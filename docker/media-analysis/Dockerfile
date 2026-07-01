FROM demisto/python3-deb:3.12.13.9224111

ENV PYTHONUNBUFFERED=1
ENV PIP_NO_CACHE_DIR=1
ENV EASYOCR_MODULE_PATH=/root/.EasyOCR

COPY requirements.txt .

RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
    libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
    libgbm1 libasound2 libpango-1.0-0 libcairo2 fonts-liberation \
    && pip install --no-cache-dir -r requirements.txt \
    && rm -rf /var/lib/apt/lists/*

RUN python -c "import easyocr; easyocr.Reader(['en','es'], gpu=False)"

RUN python -c "from pyppeteer.chromium_downloader import download_chromium; download_chromium()"
