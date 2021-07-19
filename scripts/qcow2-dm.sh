#!/bin/bash
#
# This requires parameter dm_qcow2.kernel_sets_dirty_bit=y

usage () {
    cat <<EOF
Usage:
	$prog_name create <file.qcow2> <dev_name>
	$prog_name remove <file.qcow2>
EOF
}

create () {
	if [ "$#" -ne 2 ]; then
		echo >&2 "Wrong number of arguments."; usage; exit 1;
	fi

	file=$1
	dev=$2
	files=()
	fds=""

	disk_sz=`qemu-img info -f qcow2 $file | grep "virtual size" | sed 's/.*(\(.*\) bytes)/\1/'`
	if [ -z "$disk_sz" ]; then
		echo "Can't get disk size."; exit 1;
	fi

	while :; do
		if [ ! -f "$file" ]; then
			echo "$file does not exist."; exit 1;
		fi

		files+=("$file")

		exec {fd}<>$file || exit 1
		flock -x $fd || exit 1
		fds="$fd $fds"

		file=`qemu-img info $file | grep "backing file:" | sed "s/backing file: //"`
		if [ -z "$file" ]; then
			break
		fi
	done

	echo "Create device [$dev] of size $disk_sz from [${files[*]}]."
	dmsetup create $dev --table "0 $((disk_sz / 512)) qcow2 ${fds}"
}

remove () {
	if [ "$#" -ne 1 ]; then
		echo >&2 "Wrong number of arguments."; usage; exit 1;
	fi
	user_path=$1
	path=`realpath $user_path`

	while read line; do
		dev=`echo $line | sed "s/:.*//"`
		nr_imgs=`echo $line | sed "s/.*\(\w\)$/\1/"`
		top_img_id=$((nr_imgs - 1))

		top_img_path=`dmsetup message $dev 0 get_img_name $top_img_id`
		if [ -z "$top_img_path" ]; then
			echo "Can't get image path."; exit 1;
		fi

		if [ "$path" != "$top_img_path" ]; then
			continue
		fi

		echo "Removing device [$dev]."
		dmsetup remove $dev
		ret=$?

		if [ $? -eq 0 ]; then
			#Sanity check
			echo "Checking [$top_img_path]."
			qemu-img check $top_img_path
		fi
		exit $ret

	done < <(LANG=C dmsetup table --target=qcow2 | grep -v "No devices found")

	echo "Can't find device with [$user_path] top image."
	exit 1
}

prog_name=$(basename $0)

case $1 in
	"create")
		shift
		create "$@"
		exit 0
		;;
	"remove")
		shift
		remove "$@"
		;;
	*)
		usage
		exit 1
	        ;;
esac
