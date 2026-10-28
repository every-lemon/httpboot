#!/usr/bin/env python3
"""Transfer initramfs credentials to a RAM-only NetworkManager connection."""
import os
import re
import signal
import uuid
from pathlib import Path

runtime = Path('/run/httpboot')
if (runtime/'network-type').exists() and (runtime/'network-type').read_text().strip() == 'ethernet':
    name = (runtime/'interface').read_text().strip()
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name):
        raise ValueError('Invalid Ethernet interface')
    dest = Path('/run/NetworkManager/system-connections/httpboot-wired.nmconnection')
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(f'[connection]\nid=httpboot-wired\nuuid={uuid.uuid4()}\ntype=ethernet\ninterface-name={name}\nautoconnect=true\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n')
    pidfile = runtime/'dhcp.pid'
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text()), signal.SIGTERM)
        except ProcessLookupError:
            pass

path = Path("/run/httpboot/wifi.conf")
if path.exists():
    text = path.read_text()
    match = re.search(r'^\s*ssid=(?:"(.*)"|([0-9a-fA-F]+))\s*$', text, re.M)
    if not match:
        raise ValueError("Cannot parse initramfs SSID")
    if match.group(2):
        ssid = bytes.fromhex(match.group(2))
    else:
        # wpa_passphrase quotes SSIDs; handle its escape format without eval.
        ssid = match.group(1).replace('\\"', '"').replace('\\\\', '\\').encode()
    psk = re.search(r'^\s*psk=([0-9a-fA-F]{64})\s*$', text, re.M).group(1)
    dest = Path("/run/NetworkManager/system-connections/httpboot.nmconnection")
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = (f"[connection]\nid=httpboot-ram-only\nuuid={uuid.uuid4()}\ntype=wifi\nautoconnect=true\n"
            f"[wifi]\nmode=infrastructure\nssid={';'.join(str(b) for b in ssid)};\n"
            f"[wifi-security]\nkey-mgmt=wpa-psk\npsk={psk}\n[ipv4]\nmethod=auto\n[ipv6]\nmethod=auto\n")
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as out:
        out.write(data)
    for name in ("dhcp.pid", "wpa.pid"):
        pidfile = Path("/run/httpboot") / name
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text().strip()), signal.SIGTERM)
            except ProcessLookupError:
                pass
    path.unlink()
