"""Boot-bound user leases. Offline sessions expire after fifteen minutes."""
import re
import json

GRACE = 15 * 60
BOOT = re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$')


class Leases:
    def __init__(self, authority):
        self.authority = authority
        with authority.db() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS client_presence (
                device TEXT PRIMARY KEY, boot_id TEXT, last_seen REAL);
            CREATE TABLE IF NOT EXISTS session_presence (
                name TEXT PRIMARY KEY, token TEXT, boot_id TEXT,
                last_seen REAL NOT NULL, legacy INTEGER NOT NULL DEFAULT 0);
            ''')
            # One initial grace period for pre-upgrade sessions. Restarts must
            # never renew an expired lease or change its existing token.
            for row in db.execute('SELECT name,device,token FROM sessions').fetchall():
                boot = None
                reports = authority.database.parent/'reports'/row['device']
                files = sorted(reports.glob('*.json'), key=lambda p:p.stat().st_mtime, reverse=True)
                for file in files:
                    try:
                        report=json.loads(file.read_text());candidate=report.get('boot_id')
                        if report.get('stage')=='desktop-ready' and report.get('exit_status')==0 and isinstance(candidate,str) and BOOT.fullmatch(candidate):
                            boot=candidate;break
                    except (OSError,ValueError):pass
                prior=db.execute('SELECT token FROM session_presence WHERE name=?',(row['name'],)).fetchone()
                if prior is None or prior[0]!=row['token']:
                    db.execute('INSERT OR REPLACE INTO session_presence VALUES (?,?,?,?,1)',
                               (row['name'],row['token'],boot,authority.clock()))

    def bind(self, db, name, token, peer, boot=None):
        if boot is not None and (not isinstance(boot,str) or not BOOT.fullmatch(boot)):
            raise ValueError('Invalid Client boot identity')
        legacy = boot is None
        if legacy:
            row=db.execute('SELECT boot_id FROM client_presence WHERE device=?',(peer,)).fetchone()
            boot=row[0] if row else None
        db.execute('INSERT OR REPLACE INTO session_presence VALUES (?,?,?,?,?)',
                   (name,token,boot,self.authority.clock(),int(legacy)))

    def valid(self, db, name, token):
        row=db.execute('SELECT last_seen FROM session_presence WHERE name=? AND token=?',(name,token)).fetchone()
        return row is not None and self.authority.clock()-row[0] < GRACE

    def expire(self, db):
        rows=list(db.execute('SELECT s.name FROM sessions s JOIN session_presence p '
                             'ON s.name=p.name AND s.token=p.token WHERE p.last_seen<=?',
                             (self.authority.clock()-GRACE,)))
        for row in rows:
            db.execute('DELETE FROM sessions WHERE name=?',(row[0],))
            db.execute('DELETE FROM session_presence WHERE name=?',(row[0],))
        return len(rows)

    def observe_legacy(self, peer, boot):
        if not isinstance(boot,str) or not BOOT.fullmatch(boot):return
        with self.authority.db() as db:
            now=self.authority.clock()
            self.expire(db)
            db.execute('INSERT OR REPLACE INTO client_presence VALUES (?,?,?)',(peer,boot,now))
            # Old Clients send authenticated desktop-ready reports every 30s.
            # A report from a different boot cannot renew the old boot's lock.
            db.execute('UPDATE session_presence SET boot_id=?,last_seen=? WHERE legacy=1 '
                       'AND (boot_id IS NULL OR boot_id=?) AND name IN '
                       '(SELECT name FROM sessions WHERE device=?)',(boot,now,boot,peer))

    def heartbeat(self, peer, data):
        if not isinstance(data,dict) or not isinstance(data.get('boot_id'),str) or not BOOT.fullmatch(data['boot_id']):
            raise ValueError('Invalid Client heartbeat')
        entries=data.get('sessions')
        if not isinstance(entries,list) or len(entries)>64:raise ValueError('Invalid heartbeat sessions')
        if any(not isinstance(e,dict) or set(e)!={'name','token'} or not all(isinstance(v,str) for v in e.values()) for e in entries):
            raise ValueError('Invalid heartbeat session')
        boot=data['boot_id'];result=[]
        with self.authority.db() as db:
            self.authority.device(db,peer);self.expire(db)
            now=self.authority.clock()
            db.execute('INSERT OR REPLACE INTO client_presence VALUES (?,?,?)',(peer,boot,now))
            for entry in entries:
                row=db.execute('SELECT p.boot_id FROM sessions s JOIN session_presence p ON '
                               's.name=p.name AND s.token=p.token JOIN assignments a ON '
                               's.name=a.name AND s.device=a.device WHERE s.name=? AND s.device=? AND s.token=?',
                               (entry['name'],peer,entry['token'])).fetchone()
                active=row is not None and row[0] in (None,boot)
                if active:
                    db.execute('UPDATE session_presence SET last_seen=?,boot_id=?,legacy=0 WHERE name=? AND token=?',
                               (now,boot,entry['name'],entry['token']))
                result.append({'name':entry['name'],'active':active})
        return {'ok':True,'grace_seconds':GRACE,'sessions':result}

    def release_many(self, peer, entries):
        if not isinstance(entries,list) or len(entries)>64:raise ValueError('Invalid session release')
        with self.authority.db() as db:
            self.authority.device(db,peer)
            for entry in entries:
                if not isinstance(entry,dict) or set(entry)!={'name','token'} or not all(isinstance(v,str) for v in entry.values()):raise ValueError('Invalid session release')
                row=db.execute('SELECT device,token FROM sessions WHERE name=?',(entry['name'],)).fetchone()
                if row is not None and (row['device']!=peer or row['token']!=entry['token']):
                    raise ValueError('Stale or unauthorized session; release rejected')
                if not db.execute('SELECT 1 FROM assignments WHERE name=? AND device=?',(entry['name'],peer)).fetchone():
                    raise ValueError('Account is not assigned to this Client')
            for entry in entries:
                db.execute('DELETE FROM sessions WHERE name=? AND device=? AND token=?',(entry['name'],peer,entry['token']))
                db.execute('DELETE FROM session_presence WHERE name=? AND token=?',(entry['name'],entry['token']))
        return {'ok':True}
