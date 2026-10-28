"""Server-owned durable remote build jobs and qualified publication."""
import hashlib
import json
import time
from pathlib import Path
from common import dump,load
from builder_v2 import Remote,REVISION,ARTIFACTS
from product_version import VERSION
from schedule_policy import claim,finish,defaults,due


def tick(authority,config,now):
    state=authority.database.parent/'remote-build.json';remote=Remote(config)
    job=load(state) if state.exists() else None
    if not job or job['state'] in ('published','failed'):
        with authority.db() as db:row=db.execute("SELECT value FROM settings WHERE key='schedules'").fetchone()
        policy=json.loads(row[0]) if row else defaults()
        if not due(policy,'image_updates',0,now):return {'kind':'image_updates','state':'not-due'}
    health=remote.call('/v2/health')
    if health.get('version')!=VERSION or health.get('revision')!=REVISION or health.get('architecture')!='amd64' or not health.get('healthy'):
        raise ValueError('A healthy Builder with matching build revision is required')
    if not job or job['state'] in ('published','failed'):
        token=claim(authority,'image_updates',now,{'state':'healthy','version':health['version'],'seen':now})
        if not token:return {'kind':'image_updates','state':'not-due'}
        try:
            identifier=hashlib.sha256((token+config['profile']).encode()).hexdigest()[:32]
            drivers=[]
            for record in sorted((authority.database.parent/'approved-drivers').glob('*/record.json')):
                value=load(record)
                if value.get('approved') is True:drivers.append(value)
            job={'id':identifier,'state':'submitting','created':now,'profile':config['profile'],
                 'release':'auto-'+identifier,'request':{'schema':2,'job':identifier,'profile':config['profile'],'revision':REVISION,'drivers':drivers}}
            dump(state,job)
        finally:finish(authority,token)
    if job['state']=='submitting':
        for record in job['request']['drivers']:
            remote.upload_driver(authority.database.parent/'approved-drivers'/record['sha256']/'payload',record['sha256'])
        remote.call('/v2/jobs',job['request']);job['state']='building';dump(state,job)
    status=remote.call('/v2/jobs/'+job['id'])
    if status['state']=='failed':
        job.update(state='failed',reason=status.get('reason','Remote build failed'));dump(state,job)
    elif status['state']=='complete':
        if status.get('revision')!=REVISION or set(status.get('artifacts',{}))!=ARTIFACTS:raise ValueError('Builder returned incompatible output')
        output=authority.database.parent/'remote-builds'/job['id'];output.mkdir(parents=True,exist_ok=True,mode=0o700)
        job['state']='downloading';dump(state,job)
        for name in sorted(ARTIFACTS):remote.download(job['id'],name,status['artifacts'][name],output/name)
        with authority.db() as db:published=db.execute('SELECT 1 FROM images WHERE id=?',(job['release'],)).fetchone()
        if not published:authority.images.publish(job['release'],output,output/'qualification-v2.json')
        job.update(state='published',finished=time.time());dump(state,job)
    return {'kind':'image_updates','state':job['state'],'job':job['id'],'release':job['release']}
