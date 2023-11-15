FROM demisto/chromium:119.0.6045.79948

COPY start_headless.sh start_chrome_headless.sh /

RUN    chmod +x ./start_headless.sh \
    && chmod +x ./start_chrome_headless.sh \
    && pip install -U pychrome
