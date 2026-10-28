"""Independent schedules with timezone-aware daily gates and durable run claims."""
import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
from common import load,dump
from product_version import VERSION


def defaults(timezone='UTC'):
    return {'schema':1,'timezone':timezone,'host_packages':{'enabled':True,'time':'04:00'},
            'image_updates':{'enabled':True,'time':'04:00'}}


def validate(policy):
    if not isinstance(policy,dict) or set(policy)!={'schema','timezone','host_packages','image_updates'} or policy['schema']!=1:
        raise ValueError('Invalid schedule policy')
    ZoneInfo(policy['timezone'])
    for kind in ('host_packages','image_updates'):
        schedule=policy[kind]
        if set(schedule)!={'enabled','time'} or type(schedule['enabled']) is not bool:
            raise ValueError('Invalid schedule switches')
        datetime.datetime.strptime(schedule['time'],'%H:%M')
    return policy


def read(path,legacy=False):
    return validate(load(path) if Path(path).exists() else defaults('Asia/Taipei' if legacy else 'UTC'))


def due(policy,kind,last,now):
    policy=validate(policy);schedule=policy[kind]
    if not schedule['enabled']:return False
    local=datetime.datetime.fromtimestamp(now,ZoneInfo(policy['timezone']))
    hour,minute=map(int,schedule['time'].split(':'))
    scheduled=local.replace(hour=hour,minute=minute,second=0,microsecond=0).timestamp()
    return now>=scheduled and last<scheduled


def claim(authority,kind,now,builder=None):
    with authority.db() as db:
        row=db.execute("SELECT value FROM settings WHERE key='schedules'").fetchone()
        policy=validate(__import__('json').loads(row[0])) if row else defaults()
        if not due(policy,kind,0,now):return None
        if kind=='image_updates' and (not builder or builder.get('state')!='healthy' or builder.get('version')!=VERSION or now-builder.get('seen',0)>900):
            raise ValueError(f'Healthy matching {VERSION} Builder required before image preparation')
        day=datetime.datetime.fromtimestamp(now,ZoneInfo(policy['timezone'])).date().isoformat()
        if db.execute('SELECT 1 FROM runs WHERE kind=? AND day=?',(kind,day)).fetchone():return None
        if db.execute("SELECT 1 FROM settings WHERE key='maintenance-active'").fetchone():return None
        db.execute('INSERT INTO runs VALUES (?,?)',(kind,day))
        db.execute("INSERT INTO settings VALUES ('maintenance-active',?)",(kind+':'+day,))
        return kind+':'+day


def finish(authority,claim):
    with authority.db() as db:
        db.execute("DELETE FROM settings WHERE key='maintenance-active' AND value=?",(claim,))
