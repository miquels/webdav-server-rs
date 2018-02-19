#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/quota.h>

#include "./rquota.h"
#define RQUOTA_GETQUOTA_TIMEOUT_SECS 2

static const uint32_t unlimited32 = 0xffffffff;
static const uint64_t unlimited64 = 0xffffffffffffffff;

#define E_CLNT_CALL	0x00100000
#define E_CLNT_CREATE	0x00000001
#define E_NOQUOTA	0x00000002
#define E_PERM		0x00000003
#define E_UNKNOWN	0x0000f000

static void
rquota_get_result(const rquota *rq,
		  uint64_t *bytes_used_r, uint64_t *bytes_limit_r,
		  uint64_t *files_used_r, uint64_t *files_limit_r)
{
	*bytes_used_r = (uint64_t)rq->rq_curblocks *
		(uint64_t)rq->rq_bsize;
	*bytes_limit_r = unlimited64;
	if (rq->rq_bsoftlimit != 0 && rq->rq_bsoftlimit != unlimited32) {
		*bytes_limit_r = (uint64_t)rq->rq_bsoftlimit *
			(uint64_t)rq->rq_bsize;
	} else if (rq->rq_bhardlimit != unlimited32) {
		*bytes_limit_r = (uint64_t)rq->rq_bhardlimit *
			(uint64_t)rq->rq_bsize;
	}

	*files_used_r = rq->rq_curfiles;
	*files_limit_r = unlimited64;
	if (rq->rq_fsoftlimit != 0 && rq->rq_fsoftlimit != unlimited32)
		*files_limit_r = rq->rq_fsoftlimit;
	else if (rq->rq_fhardlimit != unlimited32)
		*files_limit_r = rq->rq_fhardlimit;
}

int fs_quota_nfs_user(char *host, char *path, int uid,
	       uint64_t *bytes_used_r, uint64_t *bytes_limit_r,
	       uint64_t *files_used_r, uint64_t *files_limit_r)
{
	struct getquota_rslt result;
	struct getquota_args args;
	struct timeval timeout;
	enum clnt_stat call_status;
	CLIENT *cl;

	/* clnt_create() polls for a while to establish a connection */
	cl = clnt_create(host, RQUOTAPROG, RQUOTAVERS, "udp");
	if (cl == NULL) {
		return E_CLNT_CREATE;
	}

	/* Establish some RPC credentials */
	auth_destroy(cl->cl_auth);
	cl->cl_auth = authunix_create_default();

	/* make the rquota call on the remote host */
	args.gqa_pathp = path;
	args.gqa_uid = uid;

	timeout.tv_sec = RQUOTA_GETQUOTA_TIMEOUT_SECS;
	timeout.tv_usec = 0;
	call_status = clnt_call(cl, RQUOTAPROC_GETQUOTA,
				(xdrproc_t)xdr_getquota_args, (char *)&args,
				(xdrproc_t)xdr_getquota_rslt, (char *)&result,
				timeout);
	
	/* the result has been deserialized, let the client go */
	auth_destroy(cl->cl_auth);
	clnt_destroy(cl);

	if (call_status != RPC_SUCCESS) {
		return E_CLNT_CALL | call_status;
	}

	switch (result.status) {
	case Q_OK: {
		rquota_get_result(&result.getquota_rslt_u.gqr_rquota,
				  bytes_used_r, bytes_limit_r,
				  files_used_r, files_limit_r);
		return 0;
	}
	case Q_NOQUOTA:
		return E_NOQUOTA;
	case Q_EPERM:
		return E_PERM;
	default:
		return E_UNKNOWN;
	}
}

int fs_quota_nfs_ext(char *host, char *path, int id, int do_group,
	       uint64_t *bytes_used_r, uint64_t *bytes_limit_r,
	       uint64_t *files_used_r, uint64_t *files_limit_r)
{
#if defined(EXT_RQUOTAVERS) && defined(GRPQUOTA)
	struct getquota_rslt result;
	ext_getquota_args args;
	struct timeval timeout;
	enum clnt_stat call_status;
	CLIENT *cl;

	/* clnt_create() polls for a while to establish a connection */
	cl = clnt_create(host, RQUOTAPROG, EXT_RQUOTAVERS, "udp");
	if (cl == NULL) {
		return E_CLNT_CREATE;
	}

	/* Establish some RPC credentials */
	auth_destroy(cl->cl_auth);
	cl->cl_auth = authunix_create_default();

	/* make the rquota call on the remote host */
	args.gqa_pathp = path;
	args.gqa_id = id;
	args.gqa_type = do_group ? GRPQUOTA : USRQUOTA;
	timeout.tv_sec = RQUOTA_GETQUOTA_TIMEOUT_SECS;
	timeout.tv_usec = 0;

	call_status = clnt_call(cl, RQUOTAPROC_GETQUOTA,
				(xdrproc_t)xdr_ext_getquota_args, (char *)&args,
				(xdrproc_t)xdr_getquota_rslt, (char *)&result,
				timeout);

	/* the result has been deserialized, let the client go */
	auth_destroy(cl->cl_auth);
	clnt_destroy(cl);

	if (call_status != RPC_SUCCESS) {
		return E_CLNT_CALL | call_status;
	}

	switch (result.status) {
	case Q_OK: {
		rquota_get_result(&result.getquota_rslt_u.gqr_rquota,
				  bytes_used_r, bytes_limit_r,
				  files_used_r, files_limit_r);
		return 0;
	}
	case Q_NOQUOTA:
		return E_NOQUOTA;
	case Q_EPERM:
		return E_PERM;
	default:
		return E_UNKNOWN;
	}

	return 0;
#else
	(void)host; (void)path; (void)id; (void)do_group;
	(void)bytes_used_r; (void)bytes_limit_r;
	(void)files_used_r; (void)files_limit_r;
	return E_NOQUOTA;
#endif
}

int fs_quota_nfs(char *host, char *path, char *nfsvers, int id, int do_group,
	       uint64_t *bytes_used_r, uint64_t *bytes_limit_r,
	       uint64_t *files_used_r, uint64_t *files_limit_r)
{
	/* For NFSv4, we send the filesystem path without initial /. Server
	   prepends proper NFS pseudoroot automatically and uses this for
	   detection of NFSv4 mounts. */
	if (strcmp(nfsvers, "nfs4") == 0) {
		while (*path == '/')
			path++;
	}

	if (do_group)
		return fs_quota_nfs_ext(host, path, id, 1,
				bytes_used_r, bytes_limit_r,
				files_used_r, files_limit_r);
	else
		return fs_quota_nfs_user(host, path, id,
				bytes_used_r, bytes_limit_r,
				files_used_r, files_limit_r);
}

