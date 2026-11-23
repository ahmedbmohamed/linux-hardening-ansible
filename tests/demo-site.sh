#!/usr/bin/env bash
# Creates a FAKE "compromised" WordPress site to demo the scan and the web hardening.
# Everything planted is harmless:
#   - the "web shell" exits on its first line, so it can never run
#   - the cron job only runs /tmp/.cache-update if that file exists (it does not)
#
#   sudo bash tests/demo-site.sh           # create the demo (needs Nginx installed)
#   sudo bash tests/demo-site.sh --remove  # remove everything it created
set -euo pipefail

SITE=/var/www/demo-wp
CRON=/etc/cron.d/demo-cache-update
WEBUSER=$(id -u www-data >/dev/null 2>&1 && echo www-data || echo nginx)

if [[ "${1:-}" == "--remove" ]]; then
  rm -rf "$SITE" "$CRON" /etc/nginx/sites-enabled/demo-wp /etc/nginx/sites-available/demo-wp /etc/nginx/conf.d/demo-wp.conf
  nginx -t && systemctl reload nginx
  echo "Demo removed."
  exit 0
fi

command -v nginx >/dev/null || { echo "Install nginx first (apt install nginx / dnf install nginx)"; exit 1; }

mkdir -p "$SITE"/wp-includes "$SITE"/wp-content/uploads/2026/11 "$SITE"/wp-content/plugins/hello
cat > "$SITE/wp-config.php" <<'EOF'
<?php
// DEMO site for linux-hardening-ansible
define( 'DB_NAME', 'demo' );
define( 'DB_PASSWORD', 'demo-password' );
define( 'WP_DEBUG', true );
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
echo "<?php \$wp_version = '6.4.2';" > "$SITE/wp-includes/version.php"
echo "<html><body><h1>Demo WordPress site</h1></body></html>" > "$SITE/index.html"
echo "<?php echo 'xmlrpc';" > "$SITE/xmlrpc.php"
# Harmless fake web shell: exits before anything else
echo '<?php exit; /* DEMO */ @eval(base64_decode($_POST["x"])); ?>' > "$SITE/wp-content/uploads/2026/11/image.php"
echo "<?php // demo plugin" > "$SITE/wp-content/plugins/hello/hello.php"
chown -R "$WEBUSER:$WEBUSER" "$SITE"
chmod 644 "$SITE/wp-config.php"
chmod 666 "$SITE/wp-content/plugins/hello/hello.php"
chmod 777 "$SITE/wp-content/uploads"

# Harmless "suspicious" cron job: does nothing unless /tmp/.cache-update exists
echo '*/30 * * * * root test -x /tmp/.cache-update && /tmp/.cache-update' > "$CRON"

SERVER_BLOCK="server {
    listen 8080;
    server_name _;
    root $SITE;
    index index.html index.php;
    location / { try_files \$uri \$uri/ =404; }
}"
if [[ -d /etc/nginx/sites-available ]]; then
  echo "$SERVER_BLOCK" > /etc/nginx/sites-available/demo-wp
  ln -sf /etc/nginx/sites-available/demo-wp /etc/nginx/sites-enabled/demo-wp
else
  echo "$SERVER_BLOCK" > /etc/nginx/conf.d/demo-wp.conf
fi
if command -v getenforce >/dev/null && [[ "$(getenforce)" == "Enforcing" ]]; then
  semanage port -a -t http_port_t -p tcp 8080 2>/dev/null || semanage port -m -t http_port_t -p tcp 8080 || true
  chcon -R -t httpd_sys_content_t "$SITE" || true
fi
nginx -t
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl reload nginx
echo "Demo site ready: http://127.0.0.1:8080/  (folder $SITE)"
