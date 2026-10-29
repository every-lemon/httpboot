"""Product release identity, separate from the versioned Builder contract."""
import re

VERSION = '3.1.15-beta.2'
BUILDER_REVISION = '3.1.15-dev8'
_VERSION = re.compile(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(beta|rc)\.([1-9][0-9]*))?')


def debian_version(version=VERSION):
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise ValueError('Use MAJOR.MINOR.PATCH-beta.N, MAJOR.MINOR.PATCH-rc.N or a final version')
    return version.replace('-', '~', 1)


DEBIAN_VERSION = debian_version()
