from demisto_sdk.commands.common.MDXServer import start_local_MDX_server

with start_local_MDX_server():
    print("successfully started mdx server")