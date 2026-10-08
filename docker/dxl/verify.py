from dxlclient.broker import Broker
from dxlclient import DxlClient
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig
from dxlmarclient import ConditionConstants, MarClient, OperatorConstants, ProjectionConstants
from dxlclient.message import Event
from dxltieclient import TieClient
from dxltieclient.constants import (
    AtdAttrib,
    AtdTrustLevel,
    EnterpriseAttrib,
    FileEnterpriseAttrib,
    FileGtiAttrib,
    FileProvider,
    FileReputationProp,
    FirstRefProp,
    HashType,
    TrustLevel,
)
from dxlclient.message import Message, Request
test = Broker("test.com")

print('All packages were imported successfully')

# dxlclient requires msgpack<1.0.0: msgpack 1.x returns str instead of bytes and breaks message unpacking
request = Request("/test/topic")
request.payload = b'{"hashes":[]}'
message = Message._from_bytes(request._to_bytes())
assert message.payload == b'{"hashes":[]}', f"DXL message round-trip failed: {message.payload!r}"
print('DXL message serialization round-trip succeeded')