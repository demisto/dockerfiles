# Last modified: 2026-10-05T04:45:02.498905+00:00

FROM demisto/python3:3.12.14.13495286

COPY requirements.txt .

# The lxml wheel statically links its own libxml2/libxslt, so the system
# copies are not needed at runtime and only add an outdated parser to the image.
RUN pip install --no-cache-dir -r requirements.txt
