#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/quota.h>
#include <errno.h>

#ifdef HAVE_STRUCT_DQBLK_CURSPACE
#  define dqb_curblocks dqb_curspace
#endif

int fs_quota_linux(char *path, int id, int do_group,
		   uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		   uint64_t *count_value_r, uint64_t *count_limit_r)
{
	int type = do_group ? GRPQUOTA : USRQUOTA;

	struct dqblk dqblk;
	if (quotactl(QCMD(Q_GETQUOTA, type), path, id, (caddr_t)&dqblk) < 0) {
		if (errno == ESRCH || errno == ENOENT) {
			return 1;
		}
		return -1;
	}

#if _LINUX_QUOTA_VERSION == 1
	*bytes_value_r = dqblk.dqb_curblocks * 1024;
#else
	*bytes_value_r = dqblk.dqb_curspace;
#endif
	*bytes_limit_r = dqblk.dqb_bsoftlimit * 1024;
	if (*bytes_limit_r == 0) {
		*bytes_limit_r = dqblk.dqb_bhardlimit * 1024;
	}
	*count_value_r = dqblk.dqb_curinodes;
	*count_limit_r = dqblk.dqb_isoftlimit;
	if (*count_limit_r == 0) {
		*count_limit_r = dqblk.dqb_ihardlimit;
	}
	return 0;
}

