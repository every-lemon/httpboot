"""One fixed restore total, independent of per-folder status and save history."""
import math
import time


def amount(value):
    try:return max(0,int(value))
    except (ValueError,TypeError,OverflowError):return 0


def message(summary):
    folders=amount(summary.get('folders_total'));finished=amount(summary.get('folders_done'))
    if summary.get('stage')=='preparing':return f'Preparing saved data ({min(finished,folders)}/{folders} folders)…'
    if summary.get('stage')=='complete':return 'Saved data restored; starting your session…'
    if summary.get('stage')=='application':return f'Restoring saved application ({min(finished+1,folders)}/{folders})…'
    total=amount(summary.get('bytes_total'));done=min(amount(summary.get('bytes_done')),total)
    if not total or done==total:return f'Finishing saved data ({min(finished,folders)}/{folders} folders)…'
    divisor,unit=(1024**3,'GiB') if total>=1024**3 else (1024**2,'MiB') if total>=1024**2 else (1024,'KiB') if total>=1024 else (1,'B')
    text=f'{done/divisor:.1f} / {total/divisor:.1f} {unit} restored'
    eta=summary.get('eta_seconds')
    if isinstance(eta,(int,float)) and math.isfinite(eta) and eta>=0:text+=f', ~{int(eta)}s left'
    return text


class RestoreProgress:
    def __init__(self,status,folders,clock=None):
        self.status=status;self.clock=clock or time.monotonic;self.folders=folders
        self.finished=0;self.base=0;self.total=None;self.started=self.clock();self.preparing(0)
    def emit(self,stage,done=0):
        elapsed=max(self.clock()-self.started,0.001);speed=done/elapsed
        row={'folder':'general','operation':'restore','phase':'restored' if stage=='complete' else 'restoring',
             'stage':stage,'folders_done':self.finished,'folders_total':self.folders,'elapsed_seconds':elapsed}
        if self.total is not None:row.update(bytes_done=min(done,self.total),bytes_total=self.total,speed=speed,eta_seconds=max(0,(self.total-done)/speed) if speed else None)
        row['message']=message(row);self.status(**row)
    def preparing(self,count):self.finished=count;self.emit('preparing')
    def begin(self,total):self.total=total;self.finished=0;self.started=self.clock();self.emit('restoring')
    def update(self,**row):
        self.status(**row)
        if row.get('phase')=='restoring':self.emit('restoring',self.base+amount(row.get('bytes_done')))
    def folder_done(self,size):self.base+=size;self.finished+=1;self.emit('restoring',self.base)
    def complete(self):self.emit('complete',self.base)
