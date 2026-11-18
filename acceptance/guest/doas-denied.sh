doas_status=0
doas_output=$(LC_ALL=C doas -n id -u 2>&1) || doas_status=$?
if [ "$doas_status" -ne 1 ] || [ "$doas_output" != "doas: Operation not permitted" ]; then
    printf 'Expected doas policy denial, got exit %s and output: %s\n' "$doas_status" "$doas_output" >&2
    exit 1
fi
