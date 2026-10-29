"""Actual PTY interrupts must not abort boot, but must work after handoff."""
import fcntl,os,pty,select,shutil,signal,struct,subprocess,tempfile,termios,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('stty') and shutil.which('whiptail'),'Terminal tools unavailable')
class BootGuardTests(unittest.TestCase):
    def run_terminal(self,body,steps,timeout=15):
        with tempfile.TemporaryDirectory() as temp:
            master,slave=pty.openpty();tty=os.ttyname(slave)
            fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
            def terminal():os.setsid();fcntl.ioctl(0,termios.TIOCSCTTY,0)
            prefix='source "$1/client/boot-guard.sh"; source "$1/client/tui.sh"; boot_guard_signals; boot_guard_console; '
            process=subprocess.Popen(['bash','-c',prefix+body,'test',str(ROOT)],stdin=slave,stdout=slave,stderr=slave,
                preexec_fn=terminal,env={**os.environ,'TERM':'xterm','TTY':tty,'BOOT_GUARD_STATE':temp+'/terminal'})
            os.close(slave);raw=b'';index=0;deadline=time.monotonic()+timeout
            try:
                while time.monotonic()<deadline:
                    if select.select([master],[],[],0.05)[0]:
                        try:raw+=os.read(master,65536)
                        except OSError:break
                    if index<len(steps) and steps[index][0] in raw:
                        time.sleep(.1);os.write(master,steps[index][1]);index+=1
                    if process.poll() is not None:break
                self.assertEqual(index,len(steps),raw[-1500:])
                self.assertEqual(process.wait(timeout=2),0,raw[-1500:])
                return raw
            finally:
                if process.poll() is None:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=3)
                os.close(master)

    def test_download_survives_ctrl_c_and_handoff_restores_it(self):
        body='python3 -u -c "import time; print(\'BOOT_WORKER\',flush=True); time.sleep(.7); print(\'BOOT_FINISHED\',flush=True)"; boot_guard_restore_console; env --default-signal=INT,QUIT,TSTP python3 -u -c "import time; print(\'NORMAL_TERMINAL\',flush=True); time.sleep(20)"; code=$?; printf "HANDOFF_STATUS:%s\\n" "$code"'
        raw=self.run_terminal(body,[(b'BOOT_WORKER',b'\x03\x03'),(b'NORMAL_TERMINAL',b'\x03')])
        self.assertIn(b'BOOT_FINISHED',raw);self.assertIn(b'HANDOFF_STATUS:130',raw)

    def test_ctrl_c_does_not_cancel_menu_or_pollute_password(self):
        body='selected=$(tui_menu Choice "Choose network" n Network) || exit 9; password=$(tui_password WiFi "Enter test password") || exit 10; [[ $selected == n && $password == fixture ]] || exit 11; echo GUARDED_DIALOGS_PASSED'
        raw=self.run_terminal(body,[(b'Choose network',b'\x03'),(b'<Ok>',b'\r'),(b'Enter test password',b'\x03fixture\r')])
        self.assertIn(b'GUARDED_DIALOGS_PASSED',raw)

    def test_recovery_shell_keeps_interrupts_and_returns_to_guarded_boot(self):
        body='echo OPEN_REPAIR; boot_guard_shell; python3 -u -c "import signal; assert signal.getsignal(signal.SIGINT)==signal.SIG_IGN; print(\'BOOT_REPROTECTED\')"'
        raw=self.run_terminal(body,[(b'OPEN_REPAIR',b'echo RECOVERY_PROMPT; sleep 20\r'),(b'RECOVERY_PROMPT\r\n',b'\x03'),(b'^C',b'exit\r')])
        self.assertIn(b'BOOT_REPROTECTED',raw)

if __name__=='__main__':unittest.main()
