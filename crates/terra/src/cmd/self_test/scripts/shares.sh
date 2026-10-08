test "$(cat /work/host)" = HOST_SEED
printf linked > /work/host
ln /work/host /work/hard
printf hard-linked > /work/hard
test "$(cat /work/host)" = hard-linked
printf linked > /work/hard
ln -s host /work/link
test "$(cat /work/link)" = linked
printf open-unlink > /work/open
exec 3</work/open
rm /work/open
test "$(cat <&3)" = open-unlink
printf renamed > /work/before
mv /work/before /work/after
test "$(cat /work/after)" = renamed
printf "#!/bin/sh\necho EXECUTABLE\n" > /work/run
chmod 755 /work/run
test "$(/work/run)" = EXECUTABLE
if ln -s /work/host /work/absolute; then exit 1; fi
if ln -s /etc/passwd /work/escape; then exit 1; fi
test ! -L /work/absolute
test ! -L /work/escape
test "$(cat /readonly/seed)" = READ_ONLY
for command in ": > /readonly/new" "rm /readonly/seed" \
    "mv /readonly/seed /readonly/moved" "ln /readonly/seed /readonly/link" \
    "ln -s seed /readonly/extra-symlink"; do
    if sh -c "$command"; then exit 1; fi
done
