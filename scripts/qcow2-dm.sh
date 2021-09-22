#!/bin/bash
#
# This requires parameter dm_qcow2.kernel_sets_dirty_bit=y

usage () {
    cat <<EOF
Usage:
	$prog_name create <file.qcow2> <dev_name>
	$prog_name remove <file.qcow2>
	$prog_name check [qemu-img check optional args] <file.qcow2>
	$prog_name snapshot [qemu-img snapshot optional args] <file.qcow2>
	$prog_name resize [qemu-img resize optional args] <file.qcow2> [+ | -]size
EOF
}

get_dev_of_image () {
	abs_path=$1

	while read line; do
		dev=`echo $line | sed "s/:.*//"`
		nr_imgs=`echo $line | sed "s/.*\(\w\)$/\1/"`
		top_img_id=$((nr_imgs - 1))

		top_img_path=`dmsetup message $dev 0 get_img_name $top_img_id`
		if [ -z "$top_img_path" ]; then
			echo >&2 "Error during search of device"; exit 1;
			return 1
		fi

		if [ "$abs_path" != "$top_img_path" ]; then
			continue
		fi

		echo $dev
		return 0

	done < <(LANG=C dmsetup table --target=qcow2 | grep -v "No devices found")

	return 0
}

create () {
	if [ "$#" -ne 2 ]; then
		echo >&2 "Wrong number of arguments."; usage; exit 1;
	fi

	file=$1
	dev=$2
	files=()
	fds=""

	qemu-img check $file || exit 1

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
	abs_path=`realpath $user_path`

	dev=$(get_dev_of_image "$abs_path")
	if [ -z "$dev" ]; then
		echo >&2 "Can't find device with [$user_path] top image."; exit 1
	fi

	echo "Removing device [$dev]."
	dmsetup remove $dev
	ret=$?

	if [ $ret -eq 0 ]; then
		#Sanity check
		echo "Checking [$abs_path]."
		qemu-img check $abs_path
	fi
	exit $ret
}

qemu_img ()
{
	if [ "$#" -lt 3 ]; then
		echo >&2 "Wrong number of arguments."; usage; exit 1;
	fi

	user_path=$1
	cmd=$2
	abs_path=`realpath $user_path`
	qemu_img_args=${@: 2}

	dev=$(get_dev_of_image "$abs_path")
	if [ -z "$dev" ]; then
		echo >&2 "Can't find device by [$user_path]."; return 1
	fi

	echo "Suspending $dev"
	dmsetup suspend $dev || exit 1

	if [ "$cmd" != "check" ]; then
		echo "Checking $abs_path"
		qemu-img check $abs_path
		ret=$?
		if [ $ret -ne 0 ]; then
			echo "Resume $dev."
			dmsetup resume $dev
			exit 1
		fi
	fi

	echo "===== Call:  qemu-img $qemu_img_args. ====="
	qemu-img $qemu_img_args
	ret=$?
	if [ $ret -ne 0 ]; then
		echo >&2 "Failed during qemu-img call."
	fi
	echo "===== End of qemu-img $qemu_img_args. ====="

	echo "Resume $dev."
	dmsetup resume $dev || exit 1
	if [ $? -ne 0 ]; then
		ret=$?
	fi

	return $ret
}

check () {
	user_path=${@: -1}
	qemu_img_args=$@

	qemu_img $user_path check $qemu_img_args
	return $?
}

snapshot () {
	user_path=${@: -1}
	qemu_img_args=$@

	qemu_img $user_path snapshot $qemu_img_args
	return $?
}

resize () {
	user_path=${@:(-2):1}
	qemu_img_args=$@

	qemu_img $user_path resize $qemu_img_args
	return $?
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
	"check")
		shift
		check "$@"
		;;
	"snapshot")
		shift
		snapshot "$@"
		;;
	"resize")
		shift
		resize "$@"
		;;
	*)
		usage
		exit 1
	        ;;
esac
