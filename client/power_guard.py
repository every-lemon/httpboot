#!/usr/bin/python3
"""Block desktop power requests until HTTP Boot has saved and released users."""
import os
import signal
import subprocess
import time
from pathlib import Path
import json

def main():
    root=Path('/run/httpboot-v2');process=None
    active=root/'power-guard-active';released=root/'power-guard-released'
    active.touch(mode=0o600)
    try:
        while True:
            try:sessions=json.loads((root/'sessions.json').read_text())
            except (OSError,ValueError):sessions={}
            try:updating=json.loads((root/'update-current.json').read_text()).get('state')=='running'
            except (OSError,ValueError):updating=False
            approved=(root/'power-approved').exists()
            if (sessions or updating) and not approved and (process is None or process.poll() is not None):
                released.unlink(missing_ok=True)
                process=subprocess.Popen(['systemd-inhibit','--what=shutdown','--mode=block','--who=HTTP Boot',
                    '--why=Use HTTP Boot to save data and restart or shut down.','sleep','infinity'],start_new_session=True)
            if ((not sessions and not updating) or approved) and process is not None:
                os.killpg(process.pid,signal.SIGTERM);process.wait();process=None
            if process is None:released.touch(mode=0o600)
            time.sleep(.2)
    finally:
        if process is not None:os.killpg(process.pid,signal.SIGTERM);process.wait()
        active.unlink(missing_ok=True);released.unlink(missing_ok=True)

if __name__=='__main__':main()
