from demisto_sdk.commands.common.hook_validations.readme import ReadMeValidator, mdx_server_is_up

with ReadMeValidator.start_mdx_server():
    assert mdx_server_is_up()

print("successfully started mdx server")