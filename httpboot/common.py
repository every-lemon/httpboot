"""Shared validation. This module never evaluates configuration as code."""
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

# Compatibility identity for the retained v1 updater; v2 uses product_version.
VERSION = "3.1.14"
RECOVERY_IMAGE_LIMIT = 1_500_000_000


def recovery_size_ok(size):
    if type(size) is not int or not 0 < size <= RECOVERY_IMAGE_LIMIT:
        raise ValueError("Recovery image exceeds the 1,500,000,000-byte limit or is empty")
    return size

NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,30}$")
RELEASE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def atomic(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".new-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data.encode() if isinstance(data, str) else data)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def dump(path, value, mode=0o600):
    atomic(path, json.dumps(value, indent=2) + "\n", mode)


def load(path):
    return json.loads(Path(path).read_text())


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def identity_revision(users, hashes):
    return hashlib.sha256(json.dumps({'users':users,'hashes':hashes},sort_keys=True,separators=(',',':')).encode()).hexdigest()


def safe_url(value, https=False):
    u = urlsplit(value)
    if u.scheme not in (("https",) if https else ("http", "https")) or not u.hostname:
        raise ValueError("A valid HTTP(S) URL is required (HTTPS for updates)")
    if u.username or u.password or u.query or u.fragment or any(c.isspace() for c in value):
        raise ValueError("URLs must not contain credentials, queries, fragments, or whitespace")
    return value.rstrip("/")


def validate_config(c):
    required = {"schema", "server_ip", "allowed_clients", "boot_base_url", "data_dir", "web_dir",
                "require_data_mount", "retention", "workspace_interval", "users"}
    if c.get("schema") == 2:
        required.add("storage")
    if set(c) != required or c["schema"] not in (1, 2):
        raise ValueError("Unsupported server configuration schema")
    if ipaddress.ip_address(c["server_ip"]).version != 4:
        raise ValueError("Initial release supports an IPv4 server address")
    if not c["allowed_clients"]:
        raise ValueError("At least one allowed client network is required")
    for net in c["allowed_clients"]:
        n = ipaddress.ip_network(net, strict=True)
        if n.version != 4:
            raise ValueError("Use IPv4 client networks; 0.0.0.0/0 explicitly allows all IPv4 clients")
    safe_url(c["boot_base_url"])
    if c["boot_base_url"] != f"http://{c['server_ip']}/httpboot":
        raise ValueError("LAN v1 serves boot files at http://<server_ip>/httpboot; public HTTPS is a later extension")
    for field in ("data_dir", "web_dir"):
        p = c[field]
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", p) or ".." in Path(p).parts or p == "/":
            raise ValueError(f"Unsafe {field}")
    d, w = Path(c["data_dir"]), Path(c["web_dir"])
    if d == w or d in w.parents or w in d.parents:
        raise ValueError("Web and private data directories must be separate")
    if c['schema'] == 2:
        s = c['storage']
        if not isinstance(s, dict) or set(s) != {'uuid', 'mountpoint', 'device_id'}:
            raise ValueError('Invalid managed storage configuration')
        if not re.fullmatch(r'[a-fA-F0-9-]{16,64}', s['uuid']):
            raise ValueError('Invalid storage UUID')
        if not re.fullmatch(r'/[A-Za-z0-9_./-]+', s['mountpoint']) or '..' in Path(s['mountpoint']).parts or s['mountpoint'] == '/':
            raise ValueError('Invalid storage mount point')
        base = Path(s['mountpoint']) / 'httpboot'
        if d != base / 'data' or w != base / 'boot' or not c['require_data_mount']:
            raise ValueError('Managed storage paths must match their volume')
        if not isinstance(s['device_id'], str) or not 1 <= len(s['device_id']) <= 512:
            raise ValueError('Invalid storage device identity')
    for field, low, high in (("retention", 2, 100), ("workspace_interval", 10, 3600)):
        if type(c[field]) is not int or not low <= c[field] <= high:
            raise ValueError(f"Invalid {field}")
    if type(c["require_data_mount"]) is not bool:
        raise ValueError("require_data_mount must be boolean")
    names, uids, gids = set(), set(), set()
    reserved = {'root','daemon','bin','sys','sync','games','man','lp','mail','news','uucp','proxy','www-data','backup','list','irc','gnats','nobody','_apt','systemd-network','systemd-resolve','messagebus','syslog','sshd','avahi','polkitd','gdm','sudo','adm','disk','tty','audio','video','plugdev','netdev','input','render'}
    if not c["users"]:
        raise ValueError("Configure at least one user")
    for u in c["users"]:
        if set(u) != {"name", "uid", "gid", "visible", "workspace", "admin"}:
            raise ValueError("Invalid user fields")
        if not NAME.fullmatch(u["name"]) or u["name"] in names or u["name"] in reserved:
            raise ValueError("Invalid or duplicate username")
        for field, seen in (("uid", uids), ("gid", gids)):
            if type(u[field]) is not int or not 1000 <= u[field] <= 60000 or u[field] in seen:
                raise ValueError("UID/GID must be unique integers between 1000 and 60000")
            seen.add(u[field])
        if not all(type(u[k]) is bool for k in ("visible", "workspace", "admin")):
            raise ValueError("User flags must be boolean")
        names.add(u["name"])
    return c
