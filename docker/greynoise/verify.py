from importlib.metadata import version

from greynoise import GreyNoise
from greynoise.api import APIConfig

gn_version = version("greynoise")
assert tuple(int(p) for p in gn_version.split(".")[:2]) >= (3, 2), f"unexpected greynoise version {gn_version}"

# Build a client offline to check the SDK's config and client classes load correctly (no API call is made).
GreyNoise(APIConfig(api_key="dummy", integration_name="xsoar-verify"))

print(f"All is good. GreyNoise {gn_version} imported successfully")
