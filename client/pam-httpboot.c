/* HTTP Boot PAM conversation bridge. No passwords or user data cross this pipe. */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static int session(pam_handle_t *pamh, const char *action) {
    const char *user=NULL; const void *service=NULL;
    if (pam_get_user(pamh,&user,NULL)!=PAM_SUCCESS || !user) return PAM_SESSION_ERR;
    if (pam_get_item(pamh,PAM_SERVICE,&service)!=PAM_SUCCESS || !service) return PAM_SESSION_ERR;
    if (strcmp(service,"gdm-password") && strcmp(service,"gdm-autologin") &&
        strcmp(service,"login") && strcmp(service,"sshd")) return PAM_SUCCESS;
    int fds[2]; if (pipe(fds)) return PAM_SESSION_ERR;
    pid_t child=fork();
    if (child<0) {close(fds[0]);close(fds[1]);return PAM_SESSION_ERR;}
    if (child==0) {
        close(fds[0]);dup2(fds[1],STDOUT_FILENO);close(fds[1]);
        clearenv();setenv("PATH","/usr/sbin:/usr/bin:/sbin:/bin",1);
        setenv("PAM_USER",user,1);setenv("PAM_SERVICE",service,1);setenv("PAM_TYPE",action,1);
        execl("/usr/bin/python3","python3","/usr/local/lib/httpboot/pam-session-v2","--progress",NULL);
        _exit(127);
    }
    close(fds[1]);FILE *stream=fdopen(fds[0],"r");
    if (!stream) {close(fds[0]);return PAM_SESSION_ERR;}
    char line[512];
    while (fgets(line,sizeof(line),stream)) {
        line[strcspn(line,"\r\n")]=0;
        if (!strncmp(line,"ERROR ",6)) pam_error(pamh,"%s",line+6);
        else pam_info(pamh,"%s",line);
    }
    fclose(stream);int status=0;pid_t result;
    do {result=waitpid(child,&status,0);} while (result<0 && errno==EINTR);
    return result==child && WIFEXITED(status) && WEXITSTATUS(status)==0 ? PAM_SUCCESS : PAM_SESSION_ERR;
}
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p,int flags,int argc,const char **argv) {(void)flags;(void)argc;(void)argv;return session(p,"open_session");}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p,int flags,int argc,const char **argv) {(void)flags;(void)argc;(void)argv;return session(p,"close_session");}
