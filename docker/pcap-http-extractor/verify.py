import shutil
import struct
import tempfile
import traceback
from tempfile import NamedTemporaryFile
import pyshark

assert shutil.which('tshark'), 'tshark not found in PATH'
import subprocess
result = subprocess.run(['tshark', '--version'], capture_output=True, text=True, check=True)
assert 'TShark' in result.stdout, f'Unexpected tshark output: {result.stdout}'

# --- Verify pyshark functional: create a minimal pcap and open with FileCapture ---
pcap_hdr = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
pkt_hdr = struct.pack('<IIII', 0, 0, 0, 0)
with tempfile.NamedTemporaryFile(suffix='.pcap') as f:
    f.write(pcap_hdr + pkt_hdr)
    f.flush()
    cap = pyshark.FileCapture(f.name, display_filter='tcp')
    cap.close()

print('pcap-http-extractor is good')
