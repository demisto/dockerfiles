import importlib

# XSUP-72883: loading cv2/pyzbar runs the OpenSSL FIPS self-test at build time,
# so a wheel with a broken bundled OpenSSL fails the build here (not on a host).
# Imported dynamically for their side effects only.
for _module in ("cv2", "pyzbar.pyzbar"):
    importlib.import_module(_module)

print("qrcode verify OK")
