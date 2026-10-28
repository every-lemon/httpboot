"""Retention for registered images only. Download/build caches are never candidates."""
import json
import shutil
from pathlib import Path


def candidates(authority,now):
    with authority.db() as db:
        db.execute('CREATE TABLE IF NOT EXISTS image_pins (image TEXT, reason TEXT, PRIMARY KEY(image,reason))')
        records=list(db.execute('SELECT * FROM images ORDER BY created DESC,id DESC'))
        protected={r['id'] for r in records[:3]}|{r['id'] for r in records if r['active']}
        protected|={r[0] for r in db.execute('SELECT image FROM image_pins')}
        # An active operation can pin arbitrary deployed/rollback/card references.
        return [r['id'] for r in records if r['id'] not in protected and r['created']<now-30*86400]


def cleanup(authority,now,apply=False):
    result=candidates(authority,now)
    if not apply:return result
    # Recheck protection under the write transaction before moving anything.
    for identifier in result:
        with authority.db() as db:
            records=list(db.execute('SELECT id FROM images ORDER BY created DESC,id DESC LIMIT 3'))
            if identifier in {r[0] for r in records}:continue
            row=db.execute('SELECT active,created FROM images WHERE id=?',(identifier,)).fetchone()
            if not row or row['active'] or row['created']>=now-30*86400:continue
            if db.execute('SELECT 1 FROM image_pins WHERE image=?',(identifier,)).fetchone():continue
            source=authority.images.root/identifier
            # Rename first. On failure, the record remains visible and files are restored.
            trash=authority.images.root/('.retired-'+identifier)
            source.rename(trash)
            try:db.execute('DELETE FROM images WHERE id=?',(identifier,))
            except BaseException:trash.rename(source);raise
        shutil.rmtree(trash)
    return result


def tools(base,state,cache,now,apply=False):
    import fcntl,re
    from contextlib import ExitStack
    base=Path(base);state=Path(state);cache=Path(cache);versions=base/'versions'
    if not versions.is_dir():return []
    with ExitStack() as handles:
        for path in (state/'management.lock',state/'update.lock',cache/'worker.lock'):
            path.parent.mkdir(parents=True,exist_ok=True)
            handle=handles.enter_context(open(path,'a'))
            try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return []
        successes=[]
        for marker in (state/'tool-success').glob('*.json'):
            if not re.fullmatch(r'\d+\.\d+\.\d+',marker.stem):continue
            value=json.loads(marker.read_text());folder=versions/marker.stem
            if folder.is_dir() and not folder.is_symlink():successes.append((value['activated'],folder))
        successes.sort(reverse=True);protected={folder.name for _,folder in successes[:3]}
        current=base/'current'
        if current.is_symlink():protected.add(current.resolve().name)
        for file,field in (('last-tool-update.json','previous'),('pending-update.json','target')):
            path=state/file
            if path.exists():
                value=json.loads(path.read_text()).get(field)
                if value:protected.add(Path(value).name)
        selected=[folder for timestamp,folder in successes if folder.name not in protected and timestamp<now-30*86400]
        if apply:
            for folder in selected:
                # Actual build/download cache directories are outside this allowlist.
                retired=folder.with_name('.retired-'+folder.name);folder.rename(retired);shutil.rmtree(retired)
                (state/'tool-success'/(folder.name+'.json')).unlink(missing_ok=True)
        return [folder.name for folder in selected]
