import importlib

# XSUP-72883: loading cv2/pyzbar runs the FIPS self-test, failing the build on a broken wheel.
for _module in ("cv2", "pyzbar.pyzbar"):
    importlib.import_module(_module)

print("qrcode verify OK")
