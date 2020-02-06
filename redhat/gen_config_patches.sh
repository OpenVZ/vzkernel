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
	#
	# A sample of the input file we're parsing is:
	# # CONFIG_ARCH_RANDOM:
	# #
	# # Random number generation (part of the ARMv8.5 Extensions)
	# # provides a high bandwidth, cryptographically secure
	# # hardware random number generator.
	# #
	# # Symbol: ARCH_RANDOM [=y]
	# # Type  : bool
	# # Prompt: Enable support for random number generation
	# #   Location:
	# #	 -> Kernel Features
	# #	   -> ARMv8.5 architectural features
	# #   Defined at arch/arm64/Kconfig:1533
	# #
	# CONFIG_ARCH_RANDOM=y
	awk -v BASE=$tmpdir '
	function strip_kconfig_path(path_with_text)
	{
		sub("#.*Defined at ", "", path_with_text)
		sub(":[0-9]+", "", path_with_text)
		return path_with_text
	}
	/Defined at drivers\/net\/ethernet/ {
		# For configs in here, bundle configs by vendor
		kconfig_path=strip_kconfig_path($0);
		split(kconfig_path, path_parts, "/")
		# Only use the first component after drivers/net/ethernet
		subsystem_path=BASE"/drivers:net:ethernet:"path_parts[4]
		print config >> subsystem_path;
		next;
	}
	/Defined at drivers\/net/ {
		# For configs in here, bundle configs by driver type
		kconfig_path=strip_kconfig_path($0);
		split(kconfig_path, path_parts, "/")
		subsystem_path=BASE"/drivers:net:"path_parts[3];
		print config >> subsystem_path;
		next;
	}
	/Defined at / {
		# Bundle all other configuration by the first two components of the path
		kconfig_path=strip_kconfig_path($0);
		split(kconfig_path, path_parts, "/")
		subsystem_path=BASE"/"path_parts[1]":"path_parts[2]
		print config >> subsystem_path;
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
	# we had to change to : for the file name so switch it back
	_f=$(basename "$f" | sed -e 's/:/\//g')
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
