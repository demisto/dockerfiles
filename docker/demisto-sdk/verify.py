from demisto_sdk.commands.common.MDXServer import start_local_MDX_server
from demisto_sdk.commands.common.hook_validations.readme import mdx_server_is_up

with start_local_MDX_server():
    assert mdx_server_is_up()

print("successfully started mdx server")