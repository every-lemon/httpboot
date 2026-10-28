"""Public bootstrap only. Full images and user data have no public HTTP route."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer


def serve(authority,host='0.0.0.0',port=8080):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_HEAD(self):self.respond(False)
        def do_GET(self):self.respond(True)
        def respond(self,body):
            if self.path!='/boot.efi':self.send_error(404);return
            with authority.db(write=False) as db:row=db.execute('SELECT id FROM images WHERE active=1').fetchone()
            if not row:self.send_error(503,'No qualified bootstrap is active');return
            path=authority.images.root/row['id']/'boot.efi'
            if path.is_symlink() or not path.is_file():self.send_error(503);return
            with open(path,'rb') as stream:
                self.send_response(200);self.send_header('Content-Type','application/vnd.microsoft.portable-executable')
                self.send_header('Content-Length',str(path.stat().st_size));self.end_headers()
                if body:
                    while True:
                        block=stream.read(1024*1024)
                        if not block:break
                        self.wfile.write(block)
    with ThreadingHTTPServer((host,port),Handler) as server:server.serve_forever()
