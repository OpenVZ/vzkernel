#! /bin/bash

Dir=$1
List=$2
Dest="extra"

# Destination was specified on the command line
test -n "$3" && Dest="$3"

pushd $Dir
rm -rf modnames
find . -name "*.ko" -type f > modnames
# Look through all of the modules, and throw any that have a dependency in
# our list into the list as well.
rm -rf dep.list dep2.list
rm -rf req.list req2.list
touch dep.list req.list
cp "$List" .

# This variable needs to be exported because it is used in sub-script
# executed by xargs
export ListName=$(basename "$List")

# NB: this loop runs 2000+ iterations. Try to be fast.
NPROC=`nproc`
[ -z "$NPROC" ] && NPROC=1
cat modnames | xargs -r -n1 -P $NPROC sh -c '
  dep=$1
  depends=`modinfo $dep | sed -n -e "/^depends/ s/^depends:[ \t]*//p"`
  [ -z "$depends" ] && exit
  for mod in ${depends//,/ }
  do
    match=$(grep "^$mod.ko" "$ListName")
    [ -z "$match" ] && continue
    # check if the module we are looking at is in mod-extra too.
    # if so we do not need to mark the dep as required.
    mod2=${dep##*/}  # same as `basename $dep`, but faster
    match2=$(grep "^$mod2" "$ListName")
    if [ -n "$match2" ]
    then
      #echo $mod2 >> notreq.list
      continue
    fi
    echo $mod.ko >> req.list
  done
' DUMMYARG0   # xargs appends MODNAME, which becomes $dep in the script above

sort -u req.list > req2.list
sort -u "$ListName" > modules2.list
join -v 1 modules2.list req2.list > modules3.list

for mod in $(cat modules3.list)
do
  # get the path for the module
  modpath=`grep /$mod modnames`
  [ -z "$modpath" ] && continue
  echo $modpath >> dep.list
done

sort -u dep.list > dep2.list

# now move the modules into the extra/ directory
for mod in `cat dep2.list`
do
  newpath=`dirname $mod | sed -e "s/kernel\\//$Dest\//"`
  mkdir -p $newpath
  mv $mod $newpath
done

popd

# If we're signing modules, we can't leave the .mod files for the .ko files
# we've moved in .tmp_versions/.  Remove them so the Kbuild 'modules_sign'
# target doesn't try to sign a non-existent file.  This is kinda ugly, but
# so is modules-extra.

for mod in `cat ${Dir}/dep2.list`
do
  modfile=`basename $mod | sed -e 's/.ko/.mod/'`
  rm .tmp_versions/$modfile
done

pushd $Dir
rm modnames dep.list dep2.list req.list req2.list
rm "$ListName" modules2.list modules3.list
popd
