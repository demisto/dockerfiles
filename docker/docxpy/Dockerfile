# Last modified: 2026-11-16T05:52:41.920083+00:00

FROM demisto/python3:3.12.16.14740428

COPY requirements.txt .

# The lxml wheel statically links its own libxml2/libxslt, so the system
# copies are not needed at runtime and only add an outdated parser to the image.
RUN pip install --no-cache-dir -r requirements.txt
