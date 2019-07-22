#!/bin/sh
#
# this script is a helper script for i686 and x86_64 builds.  It gets the
# random number generator running.

echo -n "Trying hardware random number generator ..."
rngd -r /dev/hwrandom >& /dev/null
if [ $? -ne 0 ]; then
	echo "failed"
	# try the pseudo-random number generator
	echo "Using psuedo-random number instead"
	rngd -r /dev/urandom >& /dev/null
else
	echo "succeded"
fi
