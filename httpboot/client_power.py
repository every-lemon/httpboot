"""Verified power operations; never release a lease before every save succeeds."""
import json
import subprocess
import threading
import time
from pathlib import Path
from common import dump


class Power:
    def __init__(self, agent):
        self.agent=agent;self.lock=threading.Lock();self.state_lock=threading.Lock()
        self.state={'state':'idle','message':'No power operation is running'}

    def progress(self, **value):
        with self.state_lock:self.state.update(value,updated=time.time())

    def snapshot(self):
        with self.state_lock:return dict(self.state)

    def save_release(self):
        agent=self.agent
        with agent.lock:
            sessions={uid:dict(value) for uid,value in agent.sessions.items()}
        # Finish all saves before releasing any user, so one blocked application
        # cannot detach a different user's active RAM session.
        for uid in sessions:
            self.progress(state='running',message='Saving and verifying selected data')
            agent.worker(uid,'save')
        entries=[{'name':s['name'],'token':s['token']} for s in sessions.values()]
        self.progress(state='running',phase='releasing',message='Releasing verified sessions on the Server')
        if entries:agent.call('/v2/sessions/release-all',{'sessions':entries})
        with agent.lock:
            for uid,session in sessions.items():
                if agent.sessions.get(uid,{}).get('token')==session['token']:agent.sessions.pop(uid)
            dump(agent.journal,agent.sessions)
        return sessions

    def start(self, operation):
        if operation not in ('reboot','poweroff'):raise ValueError('Choose restart or shutdown')
        if not self.agent.updates.lock.acquire(False):raise ValueError('Wait for the update to finish before restarting or shutting down')
        if not self.lock.acquire(False):
            self.agent.updates.lock.release();raise ValueError('A power operation is already running')
        self.progress(state='running',phase='checking',operation=operation,message='Checking selected data before '+operation)
        def execute():
            agent=self.agent;sessions={};released=False;marker=agent.run/'power-approved'
            try:
                agent.saving_paused=True
                with agent.lock:sessions={uid:dict(value) for uid,value in agent.sessions.items()}
                self.save_release();released=True
                marker.touch(mode=0o600)
                # The guard acknowledges releasing its inhibitor. If the guard
                # is not installed (older test/deployment), logind still
                # checks any other inhibitors and can safely reject the action.
                if (agent.run/'power-guard-active').exists():
                    deadline=time.monotonic()+10
                    while not (agent.run/'power-guard-released').exists():
                        if time.monotonic()>=deadline:raise TimeoutError('Shutdown guard did not release; power action stopped')
                        time.sleep(.1)
                self.progress(state='running',message='Sessions released; '+('restarting' if operation=='reboot' else 'shutting down'))
                # systemctl --check-inhibitors=yes also rejects the requesting
                # user's own login when invoked by this root service. Role and
                # multi-user authorization was checked above the power layer.
                # logind flag 1 preserves mandatory inhibitor checks for root
                # without that CLI-only session check. Never use force/skip.
                method='RebootWithFlags' if operation=='reboot' else 'PowerOffWithFlags'
                subprocess.run(['busctl','--system','call','org.freedesktop.login1','/org/freedesktop/login1',
                    'org.freedesktop.login1.Manager',method,'t','1'],check=True,capture_output=True,text=True)
                self.progress(state='completed',message='Power action requested; sessions released')
            except Exception as error:
                # A denied system action leaves the desktop in RAM. Reacquire
                # only unclaimed leases, without restoring over current work.
                if released or self.snapshot().get('phase')=='releasing':
                    for uid,session in sessions.items():
                        if not released:
                            try:
                                agent.call('/v2/sessions/check',session);continue
                            except OSError:continue
                            except ValueError:pass
                        try:
                            token=agent.call('/v2/sessions',{'name':session['name'],'boot_id':agent.boot_id})['token']
                            with agent.lock:agent.sessions[uid]={**session,'token':token,'ready':True}
                        except Exception:pass
                    with agent.lock:dump(agent.journal,agent.sessions)
                marker.unlink(missing_ok=True)
                reason=(error.stderr or error.stdout or str(error)) if isinstance(error,subprocess.CalledProcessError) else str(error)
                self.progress(state='failed',message='Power action stopped: '+reason.strip()[:500]+'. Your RAM work and verified saves are retained.')
                agent.queue_report(error)
            finally:
                agent.saving_paused=False;self.lock.release();agent.updates.lock.release()
        threading.Thread(target=execute,daemon=True).start()
        return {'ok':True}

    def save_user(self,uid):
        if not self.lock.acquire(False):raise ValueError('Wait for the current save or power operation')
        self.progress(state='running',phase='saving',operation='save',message='Saving selected folders; quit database apps normally for verified app saves')
        def execute():
            try:
                self.agent.worker(uid,'save')
                self.progress(state='completed',message='Selected data and app sign-in save-set verified on the Server')
            except Exception as error:
                self.progress(state='failed',message='Some selected data is still pending. Inspect the folder table; your RAM work and previous verified saves are retained.')
                self.agent.queue_report(error)
            finally:self.lock.release()
        threading.Thread(target=execute,daemon=True).start()
        return {'ok':True}

    def cleanup(self):
        if (self.agent.run/'power-approved').exists():return {'ok':True}
        if not self.lock.acquire(False):raise ValueError('Power operation is already draining')
        try:
            if (self.agent.run/'power-approved').exists():return {'ok':True}
            self.agent.saving_paused=True;self.save_release()
            return {'ok':True}
        finally:self.agent.saving_paused=False;self.lock.release()


def main():
    # ExecStop also runs during an ordinary service restart. Preserve its live
    # RAM journal; cleanup is only for an actual OS shutdown/reboot.
    state=subprocess.run(['systemctl','is-system-running'],capture_output=True,text=True).stdout.strip()
    if state!='stopping':return
    from client_agent import rpc
    rpc('shutdown-cleanup')


if __name__=='__main__':main()
