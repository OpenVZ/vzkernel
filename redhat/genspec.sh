#!/bin/sh
#
# Arguments
#    SNAPSHOT: indicates whether or not this is based on an upstream tag. 1
#	indicates it is not, 0 indicates it is.

SOURCES=$1
SPECFILE=$2
CHANGELOG=$3
PKGRELEASE=$4
KVERSION=$5
KPATCHLEVEL=$6
KSUBLEVEL=$7
DISTRO_BUILD=$8
RELEASED_KERNEL=$9
SPECRELEASE=${10}
ZSTREAM_FLAG=${11}
BUILDOPTS=${12}
MARKER=${13}
LAST_MARKER=${14}
SINGLE_TARBALL=${15}
TARFILE_RELEASE=${16}
SNAPSHOT=${17}
BUILDID=${18}
RPMVERSION=${KVERSION}.${KPATCHLEVEL}.${KSUBLEVEL}
clogf="$SOURCES/changelog"
# hide [redhat] entries from changelog
HIDE_REDHAT=1;
# hide entries for unsupported arches
HIDE_UNSUPPORTED_ARCH=1;
# override LC_TIME to avoid date conflicts when building the srpm
LC_TIME=
STAMP=$(echo $MARKER | cut -f 1 -d '-' | sed -e "s/v//");
RPM_VERSION="$RPMVERSION-$PKGRELEASE";

echo >$clogf

lasttag=$(git rev-list --first-parent --grep="^\[redhat\] kernel-${RPMVERSION}" --max-count=1 HEAD)
# if we didn't find the proper tag, assume this is the first release
if [ -z "$lasttag" ]; then
	lasttag=$(git describe --match="$MARKER" --abbrev=0)
fi
# if we're doing an untagged release, just use the marker
if [ -z "$lasttag" ]; then
	echo "Using $MARKER"
	lasttag=$MARKER
fi
echo "Gathering new log entries since $lasttag"
git format-patch --no-renames -k --stdout ${lasttag}.. -- ":!/redhat/rhdocs" | awk '
BEGIN{TYPE="PATCHJUNK"; }
	# add an entry to changelog
	function changelog(subjectline, nameline, zstream)
	{
		subj = substr(subjectline, 10);
		gsub(/%/, "", subj)
		name = substr(nameline, 7);
		pos=match(name, /</);
		name=substr(name,1,pos-2);
		bz=substr(BZ,11);
		zbz=substr(ZBZ,13);
		meta = "";
		if (zstream == "no") {
			if (bz != "") {
				meta = " [" bz "]";
			}
		} else {
			if (zbz != "") {
				if (bz != "") {
					meta = " [" zbz " " bz "]";
				} else {
					meta = " [" zbz "]";
				}
			}
		}
		cve = substr(CVE, 6);
		if (cve != "") {
			if (meta != "") {
				meta = meta " {" cve "}";
			} else {
				meta = " {" cve "}";
			}
		}

		print "- " subj " (" name ")" meta >> CLOGF;
	}

	#special separator, close previous patch
	/^From / { if (TYPE=="PATCHJUNK") {
			COMMIT=substr($0, 6, 40);
			TYPE="HEADER";
			LASTHDR="NEW";
			next;
		} }

	#interesting header stuff
	/^From: / { if (TYPE=="HEADER") {
			namestr=$0;
			#check for mime encoding on the email headers
			#git uses utf-8 q encoding
			if ( $0 ~ /=\?utf-8\?q/ ) {
				#get rid of the meta utf-8 junk
				gsub(/=\?utf-8\?q\?/, "");
				gsub(/\?=/, "");

				#translate each char
				n=split($0, a, "=");
				namestr = sprintf("%s", a[1]);
				for (i = 2; i <= n; ++i) {
					utf = substr(a[i], 0, 2);
					c = strtonum("0x" utf);
					namestr = sprintf("%s%c%s", namestr, c, substr(a[i],3));
				}
			}
			NAMELINE=namestr; next;
		    }
	    }
	/^Date: / {if (TYPE=="HEADER") {DATELINE=$0; next; } }
	/^Subject: / { if (TYPE=="HEADER") {SUBJECTLINE=$0; LASTHDR="SUBJ"; next; } }
	# partially attempt to deal with RFC2822 continuation lines in headers
	/^\s/ { if (TYPE=="HEADER") { if (LASTHDR=="SUBJ") { SUBJECTLINE=(SUBJECTLINE $0); } next; } }
	/^Bugzilla: / { if (TYPE=="META") {BZ=$0; } }
	/^Z-Bugzilla: / { if (TYPE=="META") {ZBZ=$0; } }
	/^CVE: / { if (TYPE=="META") {CVE=$0; } }

	#blank line triggers end of header and to begin processing
	/^$/ { 
	    if (TYPE=="META") {
		#create the dynamic changelog entry
		changelog(SUBJECTLINE, NAMELINE, ZSTREAM);
		#reset cve values because they do not always exist
		CVE="";
		BZ="";
		ZBZ="";
		TYPE="BODY";
	    }
	    if (TYPE=="HEADER") {
		TYPE="META"; next;
	    }
	}

	#in order to handle overlapping keywords, we keep track of each
	#section of the patchfile and only process keywords in the correct section
	/^---$/ {
		if (TYPE=="META") {
			# no meta data found, just use the subject line to fill
			# the changelog
			changelog(SUBJECTLINE, NAMELINE, ZSTREAM);
			#reset cve values because they do not always exist
			CVE="";
			BZ="";
			ZBZ="";
			TYPE="BODY";
		}
		if (TYPE=="BODY") {
			TYPE="PATCHSEP";
		}
	}
	/^diff --git/ { if (TYPE=="PATCHSEP") { TYPE="PATCH"; } }
	/^-- $/ { if (TYPE=="PATCH") { TYPE="PATCHJUNK"; } }

	#filter out stuff we do not care about
	{ if (TYPE == "PATCHSEP") { next; } }
	{ if (TYPE == "PATCHJUNK") { next; } }
	{ if (TYPE == "HEADER") { next; } }

' SOURCES=$SOURCES SPECFILE=$SPECFILE CLOGF=$clogf ZSTREAM=$ZSTREAM_FLAG

cat $clogf | grep -v "tagging $RPM_VERSION" > $clogf.stripped
cp $clogf.stripped $clogf

if [ "x$HIDE_REDHAT" == "x1" ]; then
	cat $clogf | grep -v -e "^- \[redhat\]" |
		sed -e 's!\[Fedora\]!!g' > $clogf.stripped
	cp $clogf.stripped $clogf
fi

if [ "x$HIDE_UNSUPPORTED_ARCH" == "x1" ]; then
	cat $clogf | egrep -v "^- \[(alpha|arc|arm|avr32|blackfin|c6x|cris|frv|h8300|hexagon|ia64|m32r|m68k|metag|microblaze|mips|mn10300|openrisc|parisc|score|sh|sparc|tile|um|unicore32|xtensa)\]" > $clogf.stripped
	cp $clogf.stripped $clogf
fi

# If the markers aren't the same then this a rebase.
# This means we need to zap entries that are already present in the changelog.
if [ "$MARKER" != "$LAST_MARKER" ]; then
	# awk trick to get all unique lines
	awk '!seen[$0]++' $CHANGELOG $clogf > $clogf.unique
	# sed trick to get the end of the changelog minus the line
	sed -e '1,/# END OF CHANGELOG/ d' $clogf.unique > $clogf.tmp
	# Add an explicit entry to indicate a rebase.
	echo "" > $clogf
	echo -e "- $MARKER rebase" | cat $clogf.tmp - >> $clogf
	rm $clogf.tmp $clogf.unique
fi

LENGTH=$(wc -l $clogf | awk '{print $1}')

#the changelog was created in reverse order
#also remove the blank on top, if it exists
#left by the 'print version\n' logic above
cname="$(git var GIT_COMMITTER_IDENT |sed 's/>.*/>/')"
cdate="$(LC_ALL=C date +"%a %b %d %Y")"
cversion="[$RPM_VERSION]";
tac $clogf | sed "1{/^$/d; /^- /i\
* $cdate $cname $cversion
	}" > $clogf.rev

if [ "$LENGTH" = 0 ]; then
	rm -f $clogf.rev; touch $clogf.rev
fi

cat $clogf.rev $CHANGELOG > $clogf.full
mv -f $clogf.full $CHANGELOG

if [ "$SNAPSHOT" = 0 ]; then
	# This is based off a tag on Linus's tree (e.g. v5.5 or v5.5-rc5).
	# Two kernels are built, one with debug configuration and one without.
	DEBUG_BUILDS_ENABLED=1
else
	# All kernels are built with debug configurations.
	DEBUG_BUILDS_ENABLED=0
fi

if [ -n "$BUILDID" ]; then
	BUILDID_DEFINE=$(printf "%%define buildid %s" "$BUILDID")
else
	BUILDID_DEFINE="# define buildid .local"
fi

test -n "$SPECFILE" &&
        sed -i -e "
	/%%CHANGELOG%%/r $CHANGELOG
	/%%CHANGELOG%%/d
	s/%%BUILDID%%/$BUILDID_DEFINE/
	s/%%KVERSION%%/$KVERSION/
	s/%%KPATCHLEVEL%%/$KPATCHLEVEL/
	s/%%KSUBLEVEL%%/$KSUBLEVEL/
	s/%%PKGRELEASE%%/$PKGRELEASE/
	s/%%SPECRELEASE%%/$SPECRELEASE/
	s/%%DISTRO_BUILD%%/$DISTRO_BUILD/
	s/%%RELEASED_KERNEL%%/$RELEASED_KERNEL/
	s/%%DEBUG_BUILDS_ENABLED%%/$DEBUG_BUILDS_ENABLED/
	s/%%TARBALL_VERSION%%/$TARFILE_RELEASE/" $SPECFILE


# Need an empty file for dist-git compatibility
touch "$SOURCES/patch-$RPMVERSION-redhat.patch"
truncate -s 0 "$SOURCES/patch-$RPMVERSION-redhat.patch"
if [ "$SINGLE_TARBALL" = 0 ]; then
	# We want the current state of this file, not all its history
	RHELVER=$(git diff -p --stat master HEAD -- ../Makefile.rhelver)
	printf "From 8474ffe83a89d7b5d2c6515875a308ff682df6f9 Mon Sep 17 00:00:00 2001
From: Kernel Team <kernel-team@fedoraproject.org>
Date: %s
Subject: [PATCH] Include Makefile.rhelver

Used to set the RHEL version.
---
%s
--
2.26.0\n
" "$(date "+%a, %d %b %Y %R:%S %z")" "$RHELVER" > "$SOURCES/patch-$RPMVERSION-redhat.patch"

	COMMITS=$(git log --reverse --pretty=format:"%h" --no-merges "$MARKER".. \
		":(exclude,top).get_maintainer.conf" \
		":(exclude,top).gitattributes" \
		":(exclude,top).gitignore" \
		":(exclude,top).gitlab-ci.yml" \
		":(exclude,top)makefile" \
		":(exclude,top)Makefile.rhelver" \
		":(exclude,top)redhat")
	for c in $COMMITS; do
		git format-patch --stdout -1 "$c" >> "$SOURCES/patch-$RPMVERSION-redhat.patch"
	done
fi

for opt in $BUILDOPTS; do
	add_opt=
	[ -z "${opt##+*}" ] && add_opt="_with_${opt#?}"
	[ -z "${opt##-*}" ] && add_opt="_without_${opt#?}"
	[ -n "$add_opt" ] && sed -i "s/^\\(# The following build options\\)/%define $add_opt 1\\n\\1/" $SPECFILE
done

rm -f $clogf{,.rev,.stripped};
