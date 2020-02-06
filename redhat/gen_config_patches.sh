#!/bin/bash

tmpdir=$(mktemp -d)

git show -s --oneline HEAD | grep -q "AUTOMATIC: New configs"
if [ ! $? -eq 0 ]; then
	echo "The git HEAD doesn't look like the correct commit"
	exit 1
fi

# Easy way to get each of the files to process
git diff --name-only HEAD HEAD^ > /tmp/a

while read -r line; do
	# Read all the files and split up by file path of each config item.
	# ethernet and net get handled separately others can be added as needed
	awk -v BASE=$tmpdir '
	/Defined at drivers\/net\/ethernet/ {
		split($0, a);
		split(a[4], b, "/");
		OUT=BASE"/"b[1]"_"b[2]"_"b[3]"_"b[4];
		print config >> OUT;
		next;
	}
	/Defined at drivers\/net/ {
		split($0, a);
		split(a[4], b, "/");
		OUT=BASE"/"b[1]"_"b[2]"_"b[3];
		print config >> OUT;
		next;
	}
	/Defined at / {
		split($0, a);
		split(a[4], b, "/");
		split(b[2], c, ":");
		OUT=BASE"/"b[1]"_"c[1];
		print config >> OUT;
		next;
	}
	/^# CONFIG_.*:/ {
		split($0, a);
		split(a[2], b, ":");
		config=b[1];
		#print config;
	}
	' $line
done < /tmp/a

# $tmpdir now contains files containing a list of configs per file path
for f in `ls $tmpdir`; do
	# we had to change to _ for the file name so switch it back
	_f=`echo $f | sed -e 's/_/\//g'`
	# Commit subject
	echo "[redhat] New configs in $_f" > /tmp/commit
	echo "" >> /tmp/commit
	# And the boiler plate
	cat redhat/commit_template >> /tmp/commit
	# This loop actually grabs the help text to put in the commit
	while read -r line; do
		# last line is the actual config we need to put in the dir
		echo `tail -n 1 redhat/configs/pending-common/generic/$line` > redhat/configs/common/generic/$line
		# get everything except the last line for the commit text
		head -n -1 redhat/configs/pending-common/generic/$line | sed -e 's/^#//g' >> /tmp/commit
		# add a nice separator that renders in gitlab
		echo -ne "\n---\n\n" >> /tmp/commit
		# remove the pending option
		rm redhat/configs/pending-common/generic/$line
	done < $tmpdir/$f
	if [ ! -z $RHMAINTAINERS ] && [ -f ./scripts/get_maintainer.pl ] && [ -f $RHMAINTAINERS ]; then
		echo "" >> /tmp/commit
		./scripts/get_maintainer.pl --no-rolestats --mpath $RHMAINTAINERS --no-git --no-git-fallback -f $_f  | sed "s/^/Cc: /" >> /tmp/commit
	fi
	# We do a separate branch per config commit
	git checkout -b "configs/$(date +%F)/$_f"
	# One file path is done, time to commit!
	git add redhat/configs
	git commit -F /tmp/commit
	git checkout -
done

rm -rf $tmpdir
