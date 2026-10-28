#define _GNU_SOURCE
#include <pty.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <signal.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Receive one secret on stdin; age reads its own private controlling tty.
 * Plaintext uses inherited stdout, never the tty. No secret in argv/env/logs. */
static pid_t child=-1;
static void cancel(int sig){if(child>0)kill(child,SIGKILL);_exit(128+sig);}
int main(int argc,char **argv){
 if(argc!=2)return 2;
 char *secret=NULL;size_t cap=0;ssize_t size=getline(&secret,&cap,stdin);
 if(size<=1||size>4096){if(secret){explicit_bzero(secret,cap);free(secret);}return 2;}
 secret[strcspn(secret,"\r\n")]=0;
 int master,slave,status=1;struct termios tty;
 if(openpty(&master,&slave,NULL,NULL,NULL))return 2;
 tcgetattr(slave,&tty);tty.c_lflag&=~ECHO;tcsetattr(slave,TCSANOW,&tty);
 signal(SIGTERM,cancel);signal(SIGINT,cancel);signal(SIGHUP,cancel);
 child=fork();
 if(child==0){close(master);setsid();ioctl(slave,TIOCSCTTY,0);dup2(slave,0);dup2(slave,2);if(slave>2)close(slave);execl("/usr/bin/age","age","--decrypt",argv[1],(char*)NULL);_exit(127);}
 close(slave);if(child<0)return 2;
 char buffer[2048],recent[4096]={0};size_t used=0;int sent=0;
 for(int n=0;n<120;n++){
  struct pollfd fd={master,POLLIN,0};int ready=poll(&fd,1,500);
  if(ready>0){ssize_t got=read(master,buffer,sizeof(buffer)-1);if(got<=0)break;buffer[got]=0;
   if(used+(size_t)got>=sizeof(recent))used=0;
   memcpy(recent+used,buffer,(size_t)got);used+=(size_t)got;recent[used]=0;
   if(!sent&&strcasestr(recent,"passphrase")){size_t len=strlen(secret);if(write(master,secret,len)!=(ssize_t)len||write(master,"\n",1)!=1)break;sent=1;explicit_bzero(secret,cap);}
  }
  if(waitpid(child,&status,WNOHANG)==child){child=-1;break;}
 }
 if(child>0){if(waitpid(child,&status,WNOHANG)==0){kill(child,SIGKILL);waitpid(child,&status,0);}}
 close(master);explicit_bzero(secret,cap);free(secret);
 return WIFEXITED(status)?WEXITSTATUS(status):1;
}
