#!/bin/sh

if [ -z $1 ]; then
	exit 1
fi

TARGET=$1

for i in $RPM_SOURCE_DIR/*.$TARGET; do
	NEW=`echo $i | sed s/.$TARGET//`
	cp $i $NEW
done
