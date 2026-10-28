"""Exercise consecutive startup dialogs without an inherited controlling terminal."""
import fcntl
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import termios
import time
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('whiptail') and shutil.which('setsid'),'Terminal tools unavailable')
class BootTerminalTests(unittest.TestCase):
    def test_short_warning_accepts_enter_after_identity_menu(self):
        master,slave=pty.openpty();terminal=os.ttyname(slave)
        fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
        command='source "$1"; selected=$(tui_menu Identity Choose t Temporary); tui_message Warning "Temporary identity warning"; printf "DIALOGS_PASSED:%s\\n" "$selected"'
        process=subprocess.Popen(['bash','-ec',command,'test',str(ROOT/'client/tui.sh')],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TERM':'xterm','TTY':terminal},start_new_session=True)
        os.close(slave);raw=b'';menu=False;message=False;deadline=time.monotonic()+15
        try:
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:raw+=os.read(master,65536)
                    except OSError:break
                if b'Temporary' in raw and b'<Ok>' in raw and not menu:
                    time.sleep(0.3);os.write(master,b'\r');menu=True
                if b'Temporary identity warning' in raw and b'<Ok>' in raw[raw.find(b'Temporary identity warning'):] and not message:
                    time.sleep(0.3);os.write(master,b'\r');message=True
                if process.poll() is not None:break
            self.assertEqual(process.wait(timeout=2),0)
            self.assertIn(b'DIALOGS_PASSED:t',raw)
            self.assertNotIn(b'No such device or address',raw)
        finally:
            if process.poll() is None:os.killpg(process.pid,signal.SIGTERM);process.wait(timeout=3)
            os.close(master)

if __name__=='__main__':unittest.main()
