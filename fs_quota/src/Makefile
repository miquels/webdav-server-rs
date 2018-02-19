
RPCGEN	= rpcgen
CFLAGS	= -Wall

rquota.a:	quota-nfs.o rquota_xdr.o
		rm -f rquota.a
		ar r rquota.a quota-nfs.o rquota_xdr.o

rquota_xdr.c:	rquota.h
	(echo '#include <rpc/rpc.h>'; \
	 $(RPCGEN) -c rquota.x | \
	  sed -e 's/IXDR_PUT/(void)IXDR_PUT/g' \
	    -e 's,/usr/include/rpcsvc/rquota.h,rquota.h,' \
	    -e 's/^static char rcsid.*//' ) > rquota_xdr.c

rquota.h: Makefile rquota.x
	$(RPCGEN) -h rquota.x > rquota.h

rquota_xdr.o:	rquota_xdr.c
	cc -c rquota_xdr.c

quota-nfs.o:	rquota.h

clean:
	rm -f *.a *.o rquota.h rquota_clnt.c rquota_svc.c rquota_xdr.c

