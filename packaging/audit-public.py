#!/usr/bin/env python3
"""Reject credentials and private state in the exact public file set."""
import argparse
import re
from pathlib import Path

PATTERNS = (
    rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----',
    rb'\$6\$[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{86}',
    rb'\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{40,}',
    rb'gh[pousr]_[A-Za-z0-9]{30,}',
    rb'github_pat_[A-Za-z0-9_]{40,}',
)
PRIVATE_NAMES = {'.env', 'passwords', 'authority.sqlite3', 'server.key', 'client.key',
                 'ca.key', 'credentials.json', 'hosts.yml'}


def audit(paths,root):
    root=Path(root).resolve()
    count=0
    for path in paths:
        path=Path(path)
        if path.is_symlink() or not path.is_file():raise ValueError('Unexpected public file: '+path.name)
        relative=path.resolve().relative_to(root)
        if path.name in PRIVATE_NAMES or any(part in ('private','__pycache__','.ssh') for part in relative.parts):
            raise ValueError('Private state in public content: '+path.name)
        raw=path.read_bytes()
        if any(re.search(pattern,raw) for pattern in PATTERNS):
            raise ValueError('Credential pattern in public content: '+path.name)
        count+=1
    return count


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('files',type=Path,nargs='+');parser.add_argument('--root',type=Path,default=Path.cwd())
    args=parser.parse_args();print(str(audit(args.files,args.root))+' public files checked')
