"""Real terminal regression for the adapter -> SSID -> password handoff."""
import fcntl,os,pty,re,select,shutil,signal,struct,subprocess,tempfile,termios,time,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
@unittest.skipUnless(shutil.which('whiptail'),'whiptail unavailable')
class WifiDialogs(unittest.TestCase):
 def _terminal_case(self,scan_status=0):
  with tempfile.TemporaryDirectory() as temporary:
   root=Path(temporary);(root/'sys/wlan0/wireless').mkdir(parents=True);(root/'bin').mkdir();(root/'run').mkdir()
   shutil.copyfile(ROOT/'client/tui.sh',root/'tui.sh')
   paths={'/httpboot/':str(root)+'/', '/sys/class/net/':str(root/'sys')+'/', '/run/':str(root/'run')+'/'}
   script=re.sub(r'/httpboot/|/sys/class/net/|/run/',lambda match:paths[match[0]],(ROOT/'client/wifi.sh').read_text())
   script=script.replace('export PATH=/usr/sbin:/usr/bin:/sbin:/bin','export PATH='+str(root/'bin')+':/usr/sbin:/usr/bin:/sbin:/bin')
   (root/'wifi.sh').write_text(script)
   fixture='''#!/bin/bash
case ${0##*/} in
 iw) if [[ $* == *scan* ]];then if [[ ${HTTPBOOT_TEST_SCAN_STATUS:-0} != 0 ]];then echo 'fixture scan failure' >&2;exit "$HTTPBOOT_TEST_SCAN_STATUS";fi;echo 'SSID: Fixture WiFi';fi;;
 wpa_passphrase) read -r secret; printf 'network={\\n ssid="Fixture WiFi"\\n psk=fixture\\n}\\n';;
 wpa_cli) echo wpa_state=COMPLETED;;
esac
exit 0
'''
   for command in ('ip','iw','rfkill','wpa_passphrase','wpa_cli','wpa_supplicant','modprobe','dhclient'):
    file=root/'bin'/command;file.write_text(fixture);file.chmod(0o755)
   master,slave=pty.openpty();tty=os.ttyname(slave)
   fcntl.ioctl(slave,termios.TIOCSWINSZ,struct.pack('HHHH',30,100,0,0))
   # Match network.sh: a session-owning shell invokes wifi.sh as its child.
   process=subprocess.Popen(['setsid','--wait','--ctty','bash','-c','bash "$1"; echo WIFI_RESULT:$?','fixture',str(root/'wifi.sh')],stdin=slave,stdout=slave,stderr=slave,env={**os.environ,'TTY':tty,'TERM':'linux','HTTPBOOT_TEST_SCAN_STATUS':str(scan_status)})
   os.close(slave);raw=b'';stage=0;deadline=time.monotonic()+20
   try:
    while time.monotonic()<deadline:
     if select.select([master],[],[],0.1)[0]:
      try:raw+=os.read(master,65536)
      except OSError:break
     if stage==0 and b'Connect to another Wi-Fi network' in raw and b'<Ok>' in raw:
      time.sleep(.2);os.write(master,b'\r');raw=b'';stage=1
     elif stage==1 and b'Fixture WiFi' in raw and b'<Ok>' in raw:
      time.sleep(.2);os.write(master,b'\r');raw=b'';stage=2
     elif stage==1 and scan_status and b'Enter a hidden or unlisted SSID' in raw and b'<Ok>' in raw:
      time.sleep(.2);os.write(master,b'\r');raw=b'';stage=4
     elif stage==4 and b'Network name' in raw and b'<Ok>' in raw:
      time.sleep(.2);os.write(master,b'Fixture WiFi\r');raw=b'';stage=2
     elif stage==2 and b'Wi-Fi password' in raw and b'<Ok>' in raw:
      time.sleep(.2);os.write(master,b'fixture-password\r');stage=3
     if b'WIFI_RESULT:' in raw:break
    self.assertEqual(stage,3,raw[-2000:])
    self.assertIn(b'WIFI_RESULT:0',raw)
   finally:
    if process.poll() is None:process.terminate()
    process.wait(timeout=3);os.close(master)

 def test_password_prompt_after_nested_network_menus(self):self._terminal_case()
 def test_failed_scan_still_allows_manual_network_and_password(self):self._terminal_case(1)
 def test_broken_pipe_scan_still_allows_manual_network_and_password(self):self._terminal_case(141)
