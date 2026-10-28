"""Arrow-key local Server setup; all mutations use the same administration CLI."""
import curses
import subprocess
import sys
from pathlib import Path


def setup(authority,state):
    options=['Health','Boot health','Import offline report','Create/update Client USB or SD','Client approvals','Accounts','Login visibility','SSH key persistence','Assign account','Unassign account','Persistence rules','Schedules','Client policy','Flatpak repositories','Diagnostic reports','Exit']
    def ui(screen):
        selected=0;curses.curs_set(0)
        def prompt(label):
            screen.erase();screen.addstr(1,2,label);screen.addstr(3,2,'> ');screen.refresh()
            curses.echo();curses.curs_set(1)
            try:return screen.getstr(3,4,512).decode().strip()
            finally:curses.noecho();curses.curs_set(0)
        while True:
            screen.erase();screen.addstr(1,2,'HTTP Boot Server — arrows to select, Enter to continue')
            for row,label in enumerate(options,3):
                screen.addstr(row,4,label,curses.A_REVERSE if row-3==selected else curses.A_NORMAL)
            screen.refresh();key=screen.getch()
            if key==curses.KEY_UP:selected=(selected-1)%len(options)
            elif key==curses.KEY_DOWN:selected=(selected+1)%len(options)
            elif key in (10,13):
                choice=options[selected]
                if choice=='Exit':return
                command=[]
                if choice=='Health':command=['status']
                elif choice=='Boot health':command=['boot-health']
                elif choice=='Remote Builder':command=['configure-remote-builder',prompt('Protected remote Builder configuration JSON file:')]
                elif choice=='Driver imports':
                    identifier=prompt('Driver submission ID (blank to list):')
                    if identifier:
                        approve=prompt('Type APPROVE to approve, REJECT to reject:')
                        if approve not in ('APPROVE','REJECT'):continue
                        command=['review-driver',identifier]+(['--approve'] if approve=='APPROVE' else [])
                    else:command=['driver-imports']
                elif choice=='Import offline report':command=['import-report',prompt('Path to exported JSON diagnostic report:')]
                elif choice=='Create/update Client USB or SD':command=['create-media']
                elif choice=='Client approvals':command=['approve-client']
                elif choice=='Accounts':
                    name=prompt('Account name:');uid=prompt('Stable UID:');gid=prompt('Stable GID:')
                    path=prompt('Protected password hash file:');access=prompt('App access: none, status, or edit:')
                    command=['account',name,'--uid',uid,'--gid',gid,'--hash-file',path,'--access',access]
                elif choice=='Login visibility':
                    name=prompt('Account name:');visible=prompt('Show in login chooser? yes or no (typed login remains available):')
                    if visible not in ('yes','no'):continue
                    command=['account-visibility',name,'--visible' if visible=='yes' else '--no-visible']
                elif choice=='SSH key persistence':
                    name=prompt('Account name, or blank for the Server-wide default:')
                    value=prompt('Enable SSH key persistence? yes, no, or inherit (accounts only):')
                    if value not in ('yes','no','inherit') or (not name and value=='inherit'):continue
                    command=['ssh-persistence']+([name] if name else ['--default'])+['--enabled' if value=='yes' else '--no-enabled' if value=='no' else '--inherit']
                elif choice=='Assign account':command=['assign',prompt('Account name:'),prompt('Approved Client ID:')]
                elif choice=='Unassign account':command=['unassign',prompt('Account name:'),prompt('Client ID to remove (account must be logged out):')]
                elif choice=='Persistence rules':command=['set-rules',prompt('Account name:'),prompt('Rules JSON file:')]
                elif choice=='Client policy':
                    path=prompt('Client policy JSON file (blank to view):');command=['client-policy']+(['--file',path] if path else [])
                elif choice=='Flatpak repositories':
                    urls=prompt('Approved HTTPS repository URLs, separated by spaces (empty disables installs):');command=['sources',*urls.split()]
                elif choice=='Schedules':
                    path=prompt('Schedule JSON file (blank to show current):');command=['schedules']+(['--file',path] if path else [])
                elif choice=='Diagnostic reports':
                    screen.erase()
                    files=list((Path(state)/'reports').glob('*/*.json'))
                    screen.addstr(2,2,f'{len(files)} reports in {Path(state)/"reports"}');screen.getch();continue
                curses.def_prog_mode();curses.endwin()
                try:
                    subprocess.run([sys.executable,str(Path(__file__).with_name('server_v2.py')),'--state',str(state),*command],check=False)
                    input('Press Enter to return to setup…')
                finally:curses.reset_prog_mode();screen.refresh()
    curses.wrapper(ui)
