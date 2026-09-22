# Last modified: 2026-09-17T05:01:17.099150+00:00

FROM demisto/python3:3.12.14.13053055

COPY requirements.txt .

# The lxml wheel statically links its own libxml2/libxslt, so the system
# copies are not needed at runtime and only add an outdated parser to the image.
RUN pip install --no-cache-dir -r requirements.txt
