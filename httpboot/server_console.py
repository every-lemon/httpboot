"""Local administration console: health, pairing approvals and bounded boot reports."""
import hmac
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from common import atomic
from control_transport import issue

HTML=r'''<!doctype html><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>HTTP Boot Server</title><style>body{font:16px system-ui;max-width:960px;margin:40px auto;background:#111;color:#eee}button,input{font:inherit;margin:6px;padding:8px}pre{white-space:pre-wrap}</style>
<h1>HTTP Boot Server</h1><p id="health">Checking health…</p><h2>Client approvals</h2>
<input id="code" maxlength="6" placeholder="Pairing code"><div id="accountchoices"></div><button id="approve">Approve and assign accounts</button><pre id="clients"></pre>
<h2>Client boot health</h2><pre id="boothealth"></pre><h2>Diagnostic reports</h2><pre id="reports"></pre><p id="error"></p>
<script>
const token=location.hash.slice(1)||sessionStorage.getItem('token');sessionStorage.setItem('token',token||'');history.replaceState(null,'',location.pathname);
async function call(path,data){let response=await fetch(path,{method:data?'POST':'GET',headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'},body:data?JSON.stringify(data):undefined});let value=await response.json();if(!response.ok)throw Error(value.error||'Request failed');return value;}
async function refresh(){try{let state=await call('/api/state');document.getElementById('health').textContent=state.health;document.getElementById('clients').textContent=JSON.stringify(state.clients,null,2);const box=document.getElementById('accountchoices');if(!box.children.length){for(const account of state.accounts){const label=document.createElement('label'),input=document.createElement('input');input.type='checkbox';input.value=account.name;input.checked=state.defaults.includes(account.name);label.append(input,document.createTextNode(account.name+(account.system_admin?' (administrator)':' (standard user)')));box.append(label);}}document.getElementById('boothealth').textContent=JSON.stringify(state.boothealth,null,2);document.getElementById('reports').textContent=JSON.stringify(state.reports,null,2);}catch(error){document.getElementById('error').textContent=error.message;}}
document.getElementById('approve').onclick=async()=>{try{await call('/api/approve',{code:document.getElementById('code').value,accounts:Array.from(document.querySelectorAll('#accountchoices input:checked')).map(input=>input.value)});await refresh();}catch(error){document.getElementById('error').textContent=error.message;}};refresh();setInterval(refresh,10000);
</script>'''


def serve(authority,pki,port=8081):
    token=secrets.token_urlsafe(32)
    atomic(authority.database.parent/'console-token',token)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):self.respond()
        def do_POST(self):self.respond()
        def respond(self):
            self.connection.settimeout(10)
            if self.command=='GET' and self.path=='/':
                self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
                self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
                self.send_header('Cache-Control','no-store');self.end_headers();self.wfile.write(HTML.encode());return
            try:
                if not hmac.compare_digest(self.headers.get('Authorization',''),'Bearer '+token):raise ValueError('Local console credential required')
                if self.command=='GET' and self.path=='/api/state':
                    with authority.db() as db:
                        clients=[dict(row) for row in db.execute('SELECT id,hardware,code,approved,expires FROM devices')]
                    from boot_reports import sanitize
                    reports=[]
                    for path in sorted((authority.database.parent/'reports').glob('*/*.json'),key=lambda p:p.stat().st_mtime,reverse=True)[:30]:
                        try:reports.append(sanitize(json.loads(path.read_text())))
                        except (ValueError,OSError):continue
                    from boot_reports import health
                    from approval_wizard import approval_defaults
                    with authority.db() as db:accounts=[dict(row) for row in db.execute('SELECT name,system_admin FROM accounts ORDER BY uid')]
                    result={'health':'Server authority ready','clients':clients,'reports':reports,'boothealth':health(authority),'accounts':accounts,'defaults':approval_defaults(authority)}
                elif self.command=='POST' and self.path=='/api/approve':
                    size=int(self.headers.get('Content-Length','0'))
                    if not 0<size<=256:raise ValueError('Invalid approval request')
                    data=json.loads(self.rfile.read(size))
                    result={'device':authority.approve(data['code'],lambda csr,name:issue(pki,csr,name),data['accounts'])}
                else:raise ValueError('Unknown console operation')
                raw=json.dumps(result).encode();status=200
            except (ValueError,KeyError,OSError) as error:raw=json.dumps({'error':str(error)}).encode();status=400
            self.send_response(status);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store')
            self.end_headers();self.wfile.write(raw)
    if sys.stdout.isatty():print(f'Open http://127.0.0.1:{port}/#{token}',flush=True)
    else:print(f'HTTP Boot local console listening at http://127.0.0.1:{port}/; credential stored in the protected Server state',flush=True)
    with ThreadingHTTPServer(('127.0.0.1',port),Handler) as server:server.serve_forever()
