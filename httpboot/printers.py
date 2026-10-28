"""CUPS driverless discovery and queue actions. Completed documents are never saved."""
import re
import subprocess
import threading
import functools
from pathlib import Path

_cups_lock=threading.Lock()

def serialized(operation):
    @functools.wraps(operation)
    def locked(*args,**kwargs):
        # pycups stores its default username process-wide.
        with _cups_lock:return operation(*args,**kwargs)
    return locked

@serialized
def dispatch(operation,printer=None,job=None,edit=False,user=None):
    import cups
    if user is not None:cups.setUser(user)
    connection=cups.Connection()
    if operation=='list':
        printers=connection.getPrinters()
        return {'printers':[{k:v for k,v in attrs.items() if k in ('printer-info','printer-location','printer-state','printer-state-message')}
                            |{'name':name} for name,attrs in printers.items()],
                'default':connection.getDefault(),
                'jobs':[{k:v for k,v in attrs.items() if k in ('job-id','job-state','job-printer-uri','job-originating-user-name')}
                        |{'id':identifier} for identifier,attrs in connection.getJobs(which_jobs='not-completed').items()]}
    if not edit:raise ValueError('Server policy does not permit printer changes')
    if operation=='cancel':
        if type(job) is not int or job<1:raise ValueError('Invalid print job')
        attrs=connection.getJobAttributes(job)
        if user is not None and attrs.get('job-originating-user-name')!=user:
            raise ValueError('Only your own print jobs can be canceled')
        connection.cancelJob(job,purge_job=True);return {'ok':True}
    if not isinstance(printer,str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,127}',printer):
        raise ValueError('Select a printer from the available list')
    if printer not in connection.getPrinters():raise ValueError('Printer is unavailable')
    if operation=='default':connection.setDefault(printer)
    elif operation=='test':
        test=next((p for p in (Path('/usr/share/cups/data/testprint'),Path('/usr/share/cups/data/default-testpage.pdf')) if p.is_file()),None)
        if test is None:raise ValueError('CUPS test page is unavailable')
        connection.printFile(printer,str(test),'HTTP Boot test page',{})
    else:raise ValueError('Unknown printer operation')
    return {'ok':True}


def configuration():
    # Exclude spool, job history, documents and TLS/private printer credentials.
    root=Path('/etc/cups')
    result={}
    for name in ('printers.conf','classes.conf','lpoptions'):
        path=root/name
        if path.is_file():
            text=path.read_text()
            if re.search(r'(?i)(authinfo|password|://[^/\s]+@)',text):
                raise ValueError('Credential-bearing printer configuration requires separate administrator setup')
            result[name]=text
    return result


def validate_configuration(value):
    if not isinstance(value,dict) or set(value)-{'printers.conf','classes.conf','lpoptions'}:
        raise ValueError('Only printer configuration can be persisted')
    for name,text in value.items():
        if not isinstance(text,str) or len(text)>128*1024 or '\x00' in text:
            raise ValueError('Invalid printer configuration')
        if re.search(r'(?i)(authinfo|password|://[^/\s]+@)',text):
            raise ValueError('Printer credentials must be configured separately')
        if re.search(r'(?im)^\s*(?:Include|Printcap|ServerBin|ServerRoot|RequestRoot|TempDir)\b',text):
            raise ValueError('Printer configuration cannot change Server paths')
    return value


def install_configuration(value,root=Path('/etc/cups')):
    from common import atomic
    for name,text in validate_configuration(value).items():atomic(root/name,text,0o600)
