"""Review a pending Client and assign existing accounts in one transaction."""
import json
import shlex
from media_setup import Dialog,Cancelled
from control_transport import issue


def approval_defaults(authority):
    with authority.db() as db:
        row=db.execute("SELECT value FROM settings WHERE key='approval-defaults'").fetchone()
    return json.loads(row[0]) if row else []


def wizard(authority):
    ui=Dialog()
    try:
        with authority.db() as db:
            pending=list(db.execute('SELECT id,code,hardware FROM devices WHERE approved=0 AND expires>?',(authority.clock(),)))
            accounts=list(db.execute('SELECT name,system_admin FROM accounts ORDER BY uid'))
        if not pending:ui.message('Client approvals','No unexpired pending Clients. Start the Client and return here with its pairing code.');return
        if not accounts:raise ValueError('Create a Server account before approving a Client')
        code=ui.menu('Approve Client','Match the pairing code displayed on the Client:',[(row['code'],json.loads(row['hardware']).get('product_name','Client')) for row in pending])
        selected=next(row for row in pending if row['code']==code)
        ui.message('Review Client hardware',json.dumps(json.loads(selected['hardware']),indent=2))
        defaults=approval_defaults(authority)
        choices=[item for row in accounts for item in (row['name'],'Administrator' if row['system_admin'] else 'Standard user','ON' if row['name'] in defaults else 'OFF')]
        names=shlex.split(ui.call('Assign Client accounts',['--checklist','Space selects accounts. Enter continues.','22','80','12',*choices]))
        if not names:raise ValueError('Select at least one permitted account')
        if not ui.yes('Approve and assign', 'Approve pairing code '+code+' and allow these accounts: '+', '.join(names)+'?',False):return
        peer=authority.approve(code,lambda csr,name:issue(authority.database.parent/'pki',csr,name),names)
        ui.message('Client ready','Approval and account assignments saved. Client startup will continue automatically.\nClient ID: '+peer)
    except Cancelled:return


