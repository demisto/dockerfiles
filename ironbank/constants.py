# ========== Docker Directory ==========

class Pipfile:
    LOCK_NAME = 'Pipfile.lock'
    META = '_meta'
    REQUIRES = 'requires'
    DEFAULT = 'default'
    PYTHON_VERSION = 'python_version'


# ========== Hardening Manifest ==========

RESOURCE_REGEX = r'Added .+ from (https.+)#sha256=(.+) to build tracker'
DOCKERFILE_BASE_IMAGE_TAG_REGEX = r'FROM [^:]+:(.+)'

DEMISTO_REGISTRY_ROOT = 'opensource/palo-alto-networks/demisto'
DEMISTO_CONTAINERS_MAIL = 'containers@demisto.com'
PANW = 'Palo Alto Networks'
DEFAULT_USER = 'gfreund'

DOCKERFILE = 'Dockerfile'


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
