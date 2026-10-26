# Last modified: 2026-10-26T08:55:15.749210+00:00

FROM demisto/python3:3.12.15.14069087

COPY requirements.txt .

# The lxml wheel statically links its own libxml2/libxslt, so the system
# copies are not needed at runtime and only add an outdated parser to the image.
RUN pip install --no-cache-dir -r requirements.txt
