#!/bin/bash
set -e

FLAG="${FLAG:-MIPT{test_flag}}"

# Write flag
echo "$FLAG" > /home/shared/flag.txt
chown flaguser:flaguser /home/shared/flag.txt
chmod 0400 /home/shared/flag.txt

# Set SUID bit on trusted-executor
chown flaguser:flaguser /home/shared/trusted-executor
chmod 4755 /home/shared/trusted-executor

# Ensure compress.sh and its signature are readable
chown flaguser:flaguser /home/shared/compress.sh /home/shared/compress.sh.sig
chmod 0755 /home/shared/compress.sh
chmod 0644 /home/shared/compress.sh.sig

# Make shared directory accessible
chmod 0755 /home/shared

# Export all env vars for su, then run the app as 'app' user
exec su -s /bin/bash -p app -c "
  export FLAG='${FLAG}'
  export SECRET_KEY='${SECRET_KEY}'
  export ADMIN_PASSWORD='${ADMIN_PASSWORD}'
  export APP_PORT='${APP_PORT:-3000}'
  export UPLOAD_DIR='${UPLOAD_DIR:-/tmp/photos}'
  export DATABASE='${DATABASE:-/tmp/photo_storage.db}'
  export BOT_TIMEOUT='${BOT_TIMEOUT:-5000}'
  export HOME='/home/app'
  python3 /home/app/app.py
"
