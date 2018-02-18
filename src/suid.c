#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>

#if defined __x86_64__
#  define SYS_setresuid32 SYS_setresuid
#  define SYS_setresgid32 SYS_setresgid
#endif

int c_setresuid(uid_t real, uid_t effective, uid_t saved)
{
    return syscall(SYS_setresuid32, real, effective, saved);
}

int c_setresgid(gid_t real, gid_t effective, gid_t saved)
{
    return syscall(SYS_setresgid32, real, effective, saved);
}

