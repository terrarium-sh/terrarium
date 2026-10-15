test "$(wget -q -T 5 -O - "http://gate.test:$ALLOWED_PORT/")" = GUEST_NETWORK
if wget -q -T 2 -O - "http://gate.test:$DENIED_PORT/"; then exit 1; fi
if wget -q -T 2 -O - "http://blocked.invalid:$ALLOWED_PORT/"; then exit 1; fi
if nslookup blocked.invalid; then exit 1; fi
if wget -q -T 2 -O - http://192.0.2.1/; then exit 1; fi
echo NETWORK_OK
