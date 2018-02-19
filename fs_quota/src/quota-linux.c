
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/quota.h>
#include <linux/dqblk_xfs.h>
#include <errno.h>

#ifdef HAVE_STRUCT_DQBLK_CURSPACE
#  define dqb_curblocks dqb_curspace
#endif

int fs_quota_linux_xfs(char *path, int id, int do_group,
		   uint64_t *bytes_value_r, uint64_t *bytes_limit_r,
		   uint64_t *count_value_r, uint64_t *count_limit_r)
{
	int type = do_group ? GRPQUOTA : USRQUOTA;

	struct fs_disk_quota xdqblk;
	if (quotactl(QCMD(Q_XGETQUOTA, type), path, id, (caddr_t)&xdqblk) < 0) {
		if (errno == ESRCH || errno == ENOENT) {
			return 1;
		}
		return -1;
	}

	/* values always returned in 512 byte blocks */
	*bytes_value_r = xdqblk.d_bcount * 512;
	*bytes_limit_r = xdqblk.d_blk_softlimit * 512;
	if (*bytes_limit_r == 0) {
		*bytes_limit_r = xdqblk.d_blk_hardlimit * 512;
	}
	*count_value_r = xdqblk.d_icount;
	*count_limit_r = xdqblk.d_ino_softlimit;
	if (*count_limit_r == 0) {
		*count_limit_r = xdqblk.d_ino_hardlimit;
	}
	return 0;
}

int fs_quota_linux_ext(char *path, int id, int do_group,
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

