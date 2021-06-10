#!/bin/bash
kernelver=$1 && shift
arch=$1 && shift
rootfs=$1 && shift

output="${rootfs}/lib/modules/${kernelver}/crashkernel.default"

case $arch in
x86_64|s390*)
	ck_cmdline="crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M"
	;;
arm64|aarch64)
	ck_cmdline="crashkernel=2G-:448M"
	;;
powerpc|ppc64*)
	ck_cmdline="crashkernel=2G-4G:384M,4G-16G:512M,16G-64G:1G,64G-128G:2G,128G-:4G"
	;;
*)
	ck_cmdline=""
	;;
esac

cat > "$output" <<EOF
$ck_cmdline
EOF
