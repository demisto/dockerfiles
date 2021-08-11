import os
from tempfile import mkdtemp

from ironbank.build_hardening_manifest import HardeningManifest
from docker.image_latest_tag import get_latest_tag


def test_resource_handling():
    expected_outputs = [
        [
            'https://files.pythonhosted.org/packages/26/70/6d218afbe4c73538053c1016dd631e8f25fffc10cd01f5c272d7acf3c03d/bcrypt-3.2.0-cp36-abi3-manylinux2010_x86_64.whl',
            'bcrypt-3.2.0-cp36-abi3-manylinux2010_x86_64.whl',
            'cd1ea2ff3038509ea95f687256c46b79f5fc382ad0aa3664d200047546d511d1'
        ], [
            'https://files.pythonhosted.org/packages/86/c8/e3ce68952243b1e3ccf619bc11452da3723ee8adb529c1e0665a1b46b70c/cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl',
            'cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl',
            '6e4714cc64f474e4d6e37cfff31a814b509a35cb17de4fb1999907575684479c'
        ], [
            'https://files.pythonhosted.org/packages/b2/26/7af637e6a7e87258b963f1731c5982fb31cd507f0d90d91836e446955d02/cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl',
            'cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl',
            '1e056c28420c072c5e3cb36e2b23ee55e260cb04eee08f702e0edfec3fb51959'
        ], [
            'https://files.pythonhosted.org/packages/45/0b/38b06fd9b92dc2b68d58b75f900e97884c45bedd2ff83203d933cf5851c9/future-0.18.2.tar.gz',
            'future-0.18.2.tar.gz', 'b1bead90b70cf6ec3f0710ae53a525360fa360d306a86583adc6bf83a4db537d'],
        [
            'https://files.pythonhosted.org/packages/6c/79/ddb4891d2eec8e3048f748474d3de6fec7af5515477d8081a500aee70326/netmiko-3.4.0-py3-none-any.whl',
            'netmiko-3.4.0-py3-none-any.whl',
            'b66f25717db3609878f83c85604349dd40a0ab494d8eafd817dcde8388131136'
        ], [
            'https://files.pythonhosted.org/packages/7a/12/06a8425e76efcd6e18ef9eac2b37c2ee7b3c51ad8d8c891987d699a3c7eb/ntc_templates-2.0.0-py3-none-any.whl',
            'ntc_templates-2.0.0-py3-none-any.whl',
            '6617f36aaa842179e94d8b8e6527e652baf4a18a5b2f94b26b6505e5722fbc95'
        ], [
            'https://files.pythonhosted.org/packages/95/19/124e9287b43e6ff3ebb9cdea3e5e8e88475a873c05ccdf8b7e20d2c4201e/paramiko-2.7.2-py2.py3-none-any.whl',
            'paramiko-2.7.2-py2.py3-none-any.whl',
            '4f3e316fef2ac628b05097a637af35685183111d4bc1b5979bd397c2ab7b5898'
        ], [
            'https://files.pythonhosted.org/packages/ae/e7/d9c3a176ca4b02024debf82342dab36efadfc5776f9c8db077e8f6e71821/pycparser-2.20-py2.py3-none-any.whl',
            'pycparser-2.20-py2.py3-none-any.whl',
            '7582ad22678f0fcd81102833f60ef8d0e57288b6b5fb00323d101be910e35705'
        ], [
            'https://files.pythonhosted.org/packages/9d/57/2f5e6226a674b2bcb6db531e8b383079b678df5b10cdaa610d6cf20d77ba/PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl',
            'PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl',
            '30f9b96db44e09b3304f9ea95079b1b7316b2b4f3744fe3aaecccd95d547063d'
        ], [
            'https://files.pythonhosted.org/packages/07/bc/587a445451b253b285629263eb51c2d8e9bcea4fc97826266d186f96f558/pyserial-3.5-py2.py3-none-any.whl',
            'pyserial-3.5-py2.py3-none-any.whl',
            'c4451db6ba391ca6ca299fb3ec7bae67a5c55dde170964c7a14ceefec02f2cf0'
        ], [
            'https://files.pythonhosted.org/packages/b7/37/122d300034f2c8576158a7830e02c687730635e65a95f9eb2b4eb002554d/scp-0.13.3-py2.py3-none-any.whl',
            'scp-0.13.3-py2.py3-none-any.whl',
            'f2fa9fb269ead0f09b4e2ceb47621beb7000c135f272f6b70d3d9d29928d7bf0'
        ], [
            'https://files.pythonhosted.org/packages/ee/ff/48bde5c0f013094d729fe4b0316ba2a24774b3ff1c52d924a8a4cb04078a/six-1.15.0-py2.py3-none-any.whl',
            'six-1.15.0-py2.py3-none-any.whl',
            '8b74bedcbbbaca38ff6d7491d76f2b06b3592611af620f8426e82dddb04a5ced'
        ], [
            'https://files.pythonhosted.org/packages/41/ee/d6eddff86161c6a3a1753af4a66b06cbc508d3b77ca4698cd0374cd66531/tenacity-7.0.0-py2.py3-none-any.whl',
            'tenacity-7.0.0-py2.py3-none-any.whl',
            'a0ce48587271515db7d3a5e700df9ae69cce98c4b57c23a4886da15243603dd8'
        ], [
            'https://files.pythonhosted.org/packages/bd/27/0b149b6da3e47cc8daebace6920093114392171a8f5c24f1f2ad9a9e9c4d/textfsm-1.1.0-py2.py3-none-any.whl',
            'textfsm-1.1.0-py2.py3-none-any.whl',
            '0aef3f9cad3d03905915fd62bff358c42b7dc35c863ff2cb0b5324c2b746cc24'
        ]
    ]

    hardening_manifest = HardeningManifest('', '', 'ironbank/tests/test_data/docker_packages_metadata.txt')
    hardening_manifest.handle_resources()
    for index, resource in enumerate(hardening_manifest.resources):
        expected_output = expected_outputs[index]
        assert resource.url == expected_output[0]
        assert resource.filename == expected_output[1]
        assert resource.value == expected_output[2]


def test_integration():
    print(os.getcwd())
    temp_dir = mkdtemp()
    hardening_manifest = HardeningManifest('ironbank/tests/test_data/netmiko', temp_dir, 'ironbank/tests/test_data/docker_packages_metadata.txt')
    hardening_manifest.build()
    hardening_manifest.dump()
    latest_tag = get_latest_tag('demisto/netmiko')
    assert hardening_manifest.yaml_dict == {'apiVersion': 'v1', 'name': 'opensource/palo-alto-networks/demisto/netmiko',
                                            'tags': [f'{latest_tag}'],
                                            'args': {'BASE_IMAGE': 'opensource/palo-alto-networks/demisto/python3',
                                                     'BASE_TAG': '3.9.5.21272'}, 'labels': {
            'org.opencontainers.image.title': 'Demisto Automation - netmiko image',
            'org.opencontainers.image.description': 'netmiko image with the required dependencies',
            'org.opencontainers.image.licenses': ' ', 'org.opencontainers.image.url': ' ',
            'org.opencontainers.image.vendor': 'demisto', 'org.opencontainers.image.version': '1.0',
            'mil.dso.ironbank.image.keywords': 'bcrypt, cffi, cryptography, future, netmiko, ntc-templates, paramiko, pycparser, pynacl, pyserial, scp, six, tenacity, textfsm',
            'mil.dso.ironbank.image.type': 'opensource', 'mil.dso.ironbank.product.name': 'panw-demisto-netmiko'},
                                            'resources': [
                                                {'filename': 'bcrypt-3.2.0-cp36-abi3-manylinux2010_x86_64.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/26/70/6d218afbe4c73538053c1016dd631e8f25fffc10cd01f5c272d7acf3c03d/bcrypt-3.2.0-cp36-abi3-manylinux2010_x86_64.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'cd1ea2ff3038509ea95f687256c46b79f5fc382ad0aa3664d200047546d511d1'}},
                                                {'filename': 'cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/86/c8/e3ce68952243b1e3ccf619bc11452da3723ee8adb529c1e0665a1b46b70c/cffi-1.14.5-cp39-cp39-manylinux1_x86_64.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '6e4714cc64f474e4d6e37cfff31a814b509a35cb17de4fb1999907575684479c'}},
                                                {'filename': 'cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/b2/26/7af637e6a7e87258b963f1731c5982fb31cd507f0d90d91836e446955d02/cryptography-3.4.7-cp36-abi3-manylinux2014_x86_64.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '1e056c28420c072c5e3cb36e2b23ee55e260cb04eee08f702e0edfec3fb51959'}},
                                                {'filename': 'future-0.18.2.tar.gz',
                                                 'url': 'https://files.pythonhosted.org/packages/45/0b/38b06fd9b92dc2b68d58b75f900e97884c45bedd2ff83203d933cf5851c9/future-0.18.2.tar.gz',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'b1bead90b70cf6ec3f0710ae53a525360fa360d306a86583adc6bf83a4db537d'}},
                                                {'filename': 'netmiko-3.4.0-py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/6c/79/ddb4891d2eec8e3048f748474d3de6fec7af5515477d8081a500aee70326/netmiko-3.4.0-py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'b66f25717db3609878f83c85604349dd40a0ab494d8eafd817dcde8388131136'}},
                                                {'filename': 'ntc_templates-2.0.0-py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/7a/12/06a8425e76efcd6e18ef9eac2b37c2ee7b3c51ad8d8c891987d699a3c7eb/ntc_templates-2.0.0-py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '6617f36aaa842179e94d8b8e6527e652baf4a18a5b2f94b26b6505e5722fbc95'}},
                                                {'filename': 'paramiko-2.7.2-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/95/19/124e9287b43e6ff3ebb9cdea3e5e8e88475a873c05ccdf8b7e20d2c4201e/paramiko-2.7.2-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '4f3e316fef2ac628b05097a637af35685183111d4bc1b5979bd397c2ab7b5898'}},
                                                {'filename': 'pycparser-2.20-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/ae/e7/d9c3a176ca4b02024debf82342dab36efadfc5776f9c8db077e8f6e71821/pycparser-2.20-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '7582ad22678f0fcd81102833f60ef8d0e57288b6b5fb00323d101be910e35705'}},
                                                {'filename': 'PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/9d/57/2f5e6226a674b2bcb6db531e8b383079b678df5b10cdaa610d6cf20d77ba/PyNaCl-1.4.0-cp35-abi3-manylinux1_x86_64.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '30f9b96db44e09b3304f9ea95079b1b7316b2b4f3744fe3aaecccd95d547063d'}},
                                                {'filename': 'pyserial-3.5-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/07/bc/587a445451b253b285629263eb51c2d8e9bcea4fc97826266d186f96f558/pyserial-3.5-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'c4451db6ba391ca6ca299fb3ec7bae67a5c55dde170964c7a14ceefec02f2cf0'}},
                                                {'filename': 'scp-0.13.3-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/b7/37/122d300034f2c8576158a7830e02c687730635e65a95f9eb2b4eb002554d/scp-0.13.3-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'f2fa9fb269ead0f09b4e2ceb47621beb7000c135f272f6b70d3d9d29928d7bf0'}},
                                                {'filename': 'six-1.15.0-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/ee/ff/48bde5c0f013094d729fe4b0316ba2a24774b3ff1c52d924a8a4cb04078a/six-1.15.0-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '8b74bedcbbbaca38ff6d7491d76f2b06b3592611af620f8426e82dddb04a5ced'}},
                                                {'filename': 'tenacity-7.0.0-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/41/ee/d6eddff86161c6a3a1753af4a66b06cbc508d3b77ca4698cd0374cd66531/tenacity-7.0.0-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': 'a0ce48587271515db7d3a5e700df9ae69cce98c4b57c23a4886da15243603dd8'}},
                                                {'filename': 'textfsm-1.1.0-py2.py3-none-any.whl',
                                                 'url': 'https://files.pythonhosted.org/packages/bd/27/0b149b6da3e47cc8daebace6920093114392171a8f5c24f1f2ad9a9e9c4d/textfsm-1.1.0-py2.py3-none-any.whl',
                                                 'validation': {'type': 'sha256',
                                                                'value': '0aef3f9cad3d03905915fd62bff358c42b7dc35c863ff2cb0b5324c2b746cc24'}}],
                                            'maintainers': [
                                                {'email': 'containers@demisto.com', 'name': 'Palo Alto Networks',
                                                 'username': 'gfreund', 'cht_member': False}]}
    assert True
