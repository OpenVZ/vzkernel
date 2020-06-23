#!/bin/sh

for i in ${NAME}-*.config; do
	NEW=${NAME}-${VERSION}-`echo $i | cut -d - -f2-`
	mv ${i} ${NEW}
done
