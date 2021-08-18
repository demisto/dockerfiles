# ========== Docker Directory ==========

class Pipfile:
    LOCK_NAME = 'Pipfile.lock'
    META = '_meta'
    REQUIRES = 'requires'
    DEFAULT = 'default'
    PYTHON_VERSION = 'python_version'

class DockerfileMetadata:
    FILENAME = 'Dockerfile'

# ========== Hardening Manifest ==========

RESOURCE_REGEX = r'Added .+ from (https.+)#sha256=(.+) \(from -r /requirements.txt'

DEMISTO_REGISTRY_ROOT = 'opensource/palo-alto-networks/demisto'
DEMISTO_CONTAINERS_MAIL = 'containers@demisto.com'
PANW = 'Palo Alto Networks'
DEFAULT_USER = 'gfreund'


class HardeningManifestArgs:
    BASE_IMAGE = 'BASE_IMAGE'
    BASE_TAG = 'BASE_TAG'


class HardeningManifestLabels:
    TITLE = 'org.opencontainers.image.title'
    DESCRIPTION = 'org.opencontainers.image.description'
    LICENSES = 'org.opencontainers.image.licenses'
    URL = 'org.opencontainers.image.url'
    VENDOR = 'org.opencontainers.image.vendor'
    VERSION = 'org.opencontainers.image.version'
    KEYWORDS = 'mil.dso.ironbank.image.keywords'
    TYPE = 'mil.dso.ironbank.image.type'
    NAME = 'mil.dso.ironbank.product.name'
    DEMISTO = 'demisto'
    OPEN_SOURCE = 'opensource'
    BASE_NAME = 'panw-demisto'
    BASE_TITLE = 'Demisto Automation - {} image'
    BASE_DESCRIPTION = '{} image with the required dependencies'


class HardeningManifestResource:
    URL = 'url'
    FILENAME = 'filename'
    VALIDATION = 'validation'
    TYPE = 'type'
    VALUE = 'value'


class HardeningManifestYaml:
    API_VERSION = 'apiVersion'
    NAME = 'name'
    TAGS = 'tags'
    ARGS = 'args'
    LABELS = 'labels'
    RESOURCES = 'resources'
    MAINTAINERS = 'maintainers'


class HardeningManifestMaintainer:
    EMAIL = 'email'
    NAME = 'name'
    USERNAME = 'username'
    CHT_MEMBER = 'cht_member'


# ========== Dockerfile IronBank ==========

class DockerfileSections:
    HEADER = '''ARG BASE_REGISTRY=registry1.dso.mil 
ARG BASE_IMAGE={0} 
ARG BASE_TAG={1} 
FROM ${{BASE_REGISTRY}}/${{BASE_IMAGE}}:${{BASE_TAG}}'''

    DOCKER_ENV_IRON_BANK = 'ENV DOCKER_IMAGE_IRONBANK=\'{0}:{1}\''

    DOCKER_ENV_ORIGINAL = 'ENV DOCKER_IMAGE=\'{0}:{1}\''

    COPY_REQS_TXT = 'COPY requirements.txt .'

    MAKE_PIP_PKGS_DIR = 'RUN mkdir ./pip-pkgs'

    COPY_EVERYTHING_TO_PIP_PKGS = 'COPY *.* ./pip-pkgs/'

    USER_ROOT = 'USER root'

    DNF_UPDATE_BASIC_PY = '''RUN dnf install -y --nodocs python{0}-devel gcc gcc-c++ make wget git && \\  
        pip install --no-cache-dir --no-index --find-links ./pip-pkgs/ -r requirements.txt &&  \\ 
        dnf remove -y python{0}-devel gcc gcc-c++ make wget git platform-python-pip && \\
        dnf clean all && \\ 
        rm -rf /var/cache/dnf && \\
        rm -rf ./pip-pkgs'''

    FOOTER = 'HEALTHCHECK NONE '
    
    FILE_BLANK_LINE = "\n\n"
