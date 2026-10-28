"""Unprivileged encryption worker; supplied media policy is administrator controlled."""
import json
import sys
from pathlib import Path
from pending_storage import save

if __name__=='__main__':
    value=json.loads(Path(sys.argv[1]).read_text())
    print(json.dumps(save(value['home'],value['rules'],value['policy'],value['user'])))
