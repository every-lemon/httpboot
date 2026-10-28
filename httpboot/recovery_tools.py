"""Local recovery tools; no private user homes are restored in recovery."""
import json
import subprocess
from pathlib import Path


def main():
    while True:
        result=subprocess.run(['whiptail','--title','HTTP Boot recovery','--menu',
            'Recovery files are temporary. Select a repair action.','20','78','10',
            'network','Configure networking','diagnostics','Show network and boot diagnostics',
            'export','Export redacted diagnostics to USB','drivers','Inspect USB driver imports','shutdown','Shut down','return','Return to recovery desktop'],
            capture_output=True,text=True)
        if result.returncode:return
        action=result.stderr.strip()
        if action=='return':return
        if action=='network':subprocess.run(['nmtui'],check=False)
        elif action=='diagnostics':
            subprocess.run(['ip','-brief','address'],check=False);subprocess.run(['ip','route'],check=False)
            report=Path('/run/httpboot/boot-report.json')
            if report.exists():print(report.read_text()[:10000])
            input('Press Enter to return…')
        elif action=='export':
            target=subprocess.run(['whiptail','--inputbox','Mounted USB path:','10','78'],capture_output=True,text=True)
            if not target.returncode:
                from boot_reports import export_report
                try:print(json.dumps(export_report(target.stderr.strip())))
                except (OSError,ValueError) as error:print(str(error))
                input('Press Enter to return…')
        elif action=='drivers':
            media=subprocess.run(['whiptail','--inputbox','Administrator-mounted USB filesystem path:','10','78'],capture_output=True,text=True)
            if not media.returncode:
                subprocess.run(['python3',str(Path(__file__).with_name('usb_importer.py')),'--media',media.stderr.strip(),'--store','/run/httpboot-recovery-imports',*(['--server-config','/run/httpboot-v2/client-config.json'] if Path('/run/httpboot-v2/client-config.json').is_file() else [])],check=False)
        elif action=='shutdown':
            if subprocess.run(['whiptail','--yesno','Unsaved recovery files exist only in RAM. Shut down now?','10','78']).returncode==0:
                subprocess.run(['systemctl','poweroff','--check-inhibitors=yes'],check=True);return

if __name__=='__main__':main()
