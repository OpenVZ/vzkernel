#!/bin/bash

buildroot="$1"
kernel_base="$2"

blacklist()
{
	cat > "$buildroot/etc/modprobe.d/$1-blacklist.conf" <<-__EOF__
	# This kernel module can be automatically loaded by non-root users. To
	# enhance system security, the module is blacklisted by default to ensure
	# system administrators make the module available for use as needed.
	# See https://access.redhat.com/articles/3760101 for more details.
	#
	# Remove the blacklist by adding a comment # at the start of the line.
	blacklist $1
__EOF__
}

check_blacklist()
{
	if modinfo "$1" | grep -q '^alias:\s\+net-'; then
		mod="${1##*/}"
		mod="${mod%.ko*}"
		echo "$mod has an alias that allows auto-loading. Blacklisting."
		blacklist "$mod"
	fi
}

foreachp()
{
	P=$(nproc)
	bgcount=0
	while read mod; do
		$1 "$mod" &

		bgcount=$((bgcount + 1))
		if [ $bgcount -eq $P ]; then
			wait -n
			bgcount=$((bgcount - 1))
		fi
	done

	wait
}

[ -d "$buildroot/etc/modprobe.d/" ] || mkdir -p "$buildroot/etc/modprobe.d/"
find "$buildroot/$kernel_base/extra" -name "*.ko*" | \
	foreachp check_blacklist

# Many BIOS-es export a PNP-id which causes the floppy driver to autoload
# even though most modern systems don't have a 3.5" floppy driver anymore
# this replaces the old die_floppy_die.patch which removed the PNP-id from
# the module
if [ -f $buildroot/$kernel_base/extra/drivers/block/floppy.ko* ]; then
	blacklist "floppy"
fi
