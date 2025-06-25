FROM demisto/python3:3.12.8.3296088
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel \
   && pip install --no-cache-dir -r requirements.txt
