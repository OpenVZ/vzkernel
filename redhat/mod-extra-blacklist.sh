
# Many BIOS-es export a PNP-id which causes the floppy driver to autoload
# even though most modern systems don't have a 3.5" floppy driver anymore
# this replaces the old die_floppy_die.patch which removed the PNP-id from
# the module
if [ -f $buildroot/$kernel_base/extra/drivers/block/floppy.ko* ]; then
	blacklist "floppy"
fi
