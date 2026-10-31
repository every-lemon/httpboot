"""KagNode HTTP Boot startup identity and progress, with plain text fallback."""
import os
import subprocess
import sys
import time


# Generated from the canonical KagNode artwork; keep the diagonal cut and separate tile.
LOGO_WIDE = """\
            ###########
        ###############
      ################
    ##################
   ###################   ##      #   #             #   #           #
   ##################    ###     #  #   ###   #### ##  #  ###      #  ###
  ###################   #####    ###       # #   # # # # #   #  #### #   #
  ##################    ######   # #    ####  #### # # # #   # #   # #####
  ##################   ######    #  #  #   #     # #  ## #   # #   # #
  ##################   ######    #   #  ####  ###  #   #  ###   ####  #### ##
   ################   ######
    ###############   ######
     #############       ##
        ##########
"""
LOGO_COMPACT = """\
            ###########
        ###############
      ################
    ##################
   ###################   ##
   ##################    ###
  ###################   #####
  ##################    ######
  ##################   ######
  ##################   ######
   ################   ######
    ###############   ######
     #############       ##
        ##########

  KagNode.
"""
LOGO_SMALL = """\
       #######
    ##########
   ##########  #
  ###########  ##
  ##########  ####
  ##########  ###
   #########  ###
     ######

  KagNode.
"""


def startup_banner(columns=80):
    if columns >= 78: return LOGO_WIDE
    if columns >= 31: return LOGO_COMPACT
    if columns >= 19: return LOGO_SMALL
    return 'KagNode.\n'


class Progress:
    def __init__(self):
        try: columns=os.get_terminal_size(sys.stdout.fileno()).columns or 80
        except (OSError,ValueError,AttributeError): columns=80
        color=sys.stdout.isatty() and os.environ.get('TERM','') not in ('','dumb') and 'NO_COLOR' not in os.environ
        print('\n'+('\033[94m' if color else '')+startup_banner(columns)+('\033[0m' if color else '')+'\n  HTTP Boot\n',flush=True)
        self.process=None;self.console=None;self.last=0;self.started=time.monotonic();self.label='Preparing startup'
        self.interactive=sys.stdin.isatty() and os.environ.get('TERM','')!='dumb'
    def stage(self,label):
        self.close();self.label=label;self.started=time.monotonic();self.last=0
        if not self.interactive:print(label,flush=True)
        else:
            with open(os.ttyname(sys.stdin.fileno()) if sys.stdin.isatty() else '/dev/console','w') as console:
                subprocess.run(['whiptail','--title','KagNode. HTTP Boot','--infobox',label,'10','78'],stdout=console,stderr=console,check=False)
    def message(self,text):
        self.stage(text)
    def progress(self,**values):
        now=time.monotonic()
        done,total=values['bytes_done'],values['bytes_total']
        if now-self.last<0.2 and done!=total:return
        self.last=now;elapsed=int(now-self.started);eta=values.get('eta_seconds')
        line=f"{self.label}\n{done/1024**2:.1f} / {total/1024**2:.1f} MiB | {values.get('bytes_per_second',0)/1024**2:.1f} MiB/s\nElapsed {elapsed}s | ETA {int(eta) if eta is not None else 'unknown'}s"
        if not self.interactive:print(line.replace('\n',' | '),flush=True);return
        try:
            if self.process is None:
                self.console=open(os.ttyname(sys.stdin.fileno()) if sys.stdin.isatty() else '/dev/console','w')
                self.process=subprocess.Popen(['whiptail','--title','KagNode. HTTP Boot','--gauge',line,'12','78','0'],stdin=subprocess.PIPE,stdout=self.console,stderr=self.console,text=True)
            percent=min(100,int(done*100/total)) if total else 0
            self.process.stdin.write(f'XXX\n{percent}\n{line}\nXXX\n');self.process.stdin.flush()
        except (OSError,BrokenPipeError):
            self.close();self.interactive=False;print(line,flush=True)
    def close(self):
        if self.process:
            try:self.process.stdin.close();self.process.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):self.process.terminate();self.process.wait(timeout=3)
            self.process=None
        if self.console:self.console.close();self.console=None
