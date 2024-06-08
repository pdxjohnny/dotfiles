#!/usr/bin/env bash
set -xeuo pipefail

mkdir -p $HOME/.local/share/systemd/user

tee $HOME/.local/share/systemd/user/forge.service <<'EOF'
[Unit]
Description=Secure Softare Forge
[Service]
Type=simple
TimeoutStartSec=0
ExecStart=bash -c "exec ${HOME}/.local/share/systemd/user/forge.service.sh"
[Install]
WantedBy=default.target
EOF

touch $HOME/.local/share/systemd/user/forge.service.sh
chmod 755 $HOME/.local/share/systemd/user/forge.service.sh
tee $HOME/.local/share/systemd/user/forge.service.sh <<'EOF'
#!/usr/bin/env bash
set -xeuo pipefail

export FORGEJO_FQDN="git.pdxjohnny.chadig.com"
export DIRECTUS_FQDN="directus.pdxjohnny.chadig.com"

rm -fv \
  "${HOME}/.local/directus.sqlite3" \
  "${HOME}/.local/directus_admin_role_id.txt"

referesh_role_id() {
  set -x
  export DIRECTUS_ADMIN_ROLE_ID=$(echo 'SELECT id from directus_roles;' \
                                  | sqlite3 ${HOME}/.local/directus.sqlite3 \
                                  | tee ${HOME}/.local/directus_admin_role_id.txt)
  set +x
}

wait_for_and_populate_directus_admin_role_id_txt() {
  set +x
  referesh_role_id
  while [ "x" = "x${DIRECTUS_ADMIN_ROLE_ID}" ]; do
    sleep 0.01
    referesh_role_id
  done
  set -x
}

wait_for_and_populate_directus_admin_role_id_txt &

DIRECTUS_CONTAINER_ID=$(docker run \
  --detach \
  -p 8055:8055 \
  -e PUBLIC_URL="https://${DIRECTUS_FQDN}" \
  -e AUTH_DISABLE_DEFAULT=true \
  -e AUTH_PROVIDERS="forgejo" \
  -e AUTH_FORGEJO_DRIVER="openid" \
  -e AUTH_FORGEJO_CLIENT_ID="$(python -m keyring get directus auth.forgejo.client_id)" \
  -e AUTH_FORGEJO_CLIENT_SECRET="$(python -m keyring get directus auth.forgejo.client_secret)" \
  -e AUTH_FORGEJO_ISSUER_URL="https://${FORGEJO_FQDN}/.well-known/openid-configuration" \
  -e AUTH_FORGEJO_IDENTIFIER_KEY="email" \
  -e AUTH_FORGEJO_REDIRECT_ALLOW_LIST="https://${DIRECTUS_FQDN}/auth/login/forgejo/callback" \
  -e AUTH_FORGEJO_ALLOW_PUBLIC_REGISTRATION=true \
  -e SECRET="$(head -n 99999 /dev/urandom | sha384sum - | awk '{print $1}')" \
  --entrypoint sh \
  -v "${HOME}/.local/directus_admin_role_id.txt:/directus/admin_role_id.txt:z" \
  -v "${HOME}/.local/directus.sqlite3:/directus/database/database.sqlite:z" \
  directus/directus \
  -c \
  'set -x && node cli.js bootstrap && while [ "x$(cat admin_role_id.txt)" = "x" ]; do sleep 10; done && export AUTH_FORGEJO_DEFAULT_ROLE_ID=$(cat admin_role_id.txt) && pm2-runtime start ecosystem.config.cjs')

GITEA_WORK_DIR=$HOME/.local/appdata forgejo web &
FORGEJO_PID=$!

cleanup() {
  kill "${FORGEJO_PID}"
  docker kill "${DIRECTUS_CONTAINER_ID}"
}

trap cleanup EXIT

==> /home/pdxjohnny/Documents/python/dffml/examples/tutorials/rolling_alice/federated_forge/alice_and_bob/requests/alice/app.ini <==
APP_NAME = Forgejo: Beyond coding. We forge.
RUN_USER = git
RUN_MODE = prod

[repository]
ROOT = /var/lib/gitea/git/repositories

[repository.local]
LOCAL_COPY_PATH = /tmp/gitea/local-repo

[repository.upload]
TEMP_PATH = /tmp/gitea/uploads

[server]
APP_DATA_PATH = /var/lib/gitea
SSH_DOMAIN       = localhost
HTTP_PORT        = 2000
ROOT_URL         = 
DISABLE_SSH      = false
; In rootless gitea container only internal ssh server is supported
START_SSH_SERVER = true
SSH_PORT         = 2222
SSH_LISTEN_PORT  = 2222
BUILTIN_SSH_SERVER_USER = git
LFS_START_SERVER = 

[database]
PATH = /var/lib/gitea/data/gitea.db
DB_TYPE = sqlite3
HOST    = localhost:3306
NAME    = gitea
USER    = root
PASSWD  = 

[session]
PROVIDER_CONFIG = /var/lib/gitea/data/sessions

[picture]
AVATAR_UPLOAD_PATH = /var/lib/gitea/data/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /var/lib/gitea/data/repo-avatars

[attachment]
PATH = /var/lib/gitea/data/attachments

[log]
ROOT_PATH = /var/lib/gitea/data/log

[security]
INSTALL_LOCK = false
SECRET_KEY   = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW  = false

[lfs]
PATH = /var/lib/gitea/git/lfs

==> /home/pdxjohnny/Documents/python/dffml/examples/tutorials/rolling_alice/federated_forge/alice_and_bob/requests/alice/init.yaml <==
app_name: 'Forgejo: Beyond coding. We forge.'
app_url: http://127.0.0.1:2000/
charset: utf8
db_host: localhost:3306
db_name: gitea
db_path: /var/lib/gitea/data/gitea.db
db_type: sqlite3
db_user: root
default_allow_create_organization: 'on'
default_enable_timetracking: 'on'
domain: alice_forgejo_server
enable_federated_avatar: 'on'
enable_open_id_sign_in: 'on'
enable_open_id_sign_up: 'on'
http_port: '2000'
lfs_root_path: /var/lib/gitea/git/lfs
log_root_path: /var/lib/gitea/data/log
no_reply_address: noreply.localhost
password_algorithm: pbkdf2_hi
repo_root_path: /var/lib/gitea/git/repositories
run_user: git
ssh_port: '2022'
ssl_mode: disable

==> /home/pdxjohnny/Documents/python/dffml/examples/tutorials/rolling_alice/federated_forge/alice_and_bob/requests/alice/sign_up.yaml <==
_csrf: CSRF_TOKEN
email: alice@chadig.com
password: maryisgod
retype: maryisgod
user_name: alice

==> /home/pdxjohnny/Documents/python/dffml/examples/tutorials/rolling_alice/federated_forge/alice_and_bob/requests/scripts/forgejo-first-time-init.sh <==
echo "awaiting-forgejo";
until curl -I "${FORGEJO_SERVICE_ROOT}" > /dev/null 2>&1; do sleep 0.1; done;

echo "checking-if-forgejo-need-first-time-init";
query_params=$(python3 -c 'import sys, urllib.parse, yaml; print(urllib.parse.urlencode(yaml.safe_load(sys.stdin)))' < /usr/src/forgejo-init/requests/init.yaml);
curl -v -X POST --data-raw "${query_params}" "${FORGEJO_SERVICE_ROOT}" > /dev/null;
echo "forgejo-first-time-init-complete";

get_sign_up_crsf_token() {
  curl "${1}/user/sign_up" | grep csrfToken | awk '{print $NF}' | sed -e "s/'//g" -e 's/,//g'
}

echo "creating-forgejo-admin-user";
CSRF_TOKEN=$(get_sign_up_crsf_token "${FORGEJO_SERVICE_ROOT}");
while [ "x${CSRF_TOKEN}" == "x" ]; do
  CSRF_TOKEN=$(get_sign_up_crsf_token "${FORGEJO_SERVICE_ROOT}");
  sleep 0.1;
done
query_params=$(
  sed -e "s/CSRF_TOKEN/\"${CSRF_TOKEN}\"/g" /usr/src/forgejo-init/requests/sign_up.yaml \
    | python3 -c 'import sys, urllib.parse, yaml; print(urllib.parse.urlencode(yaml.safe_load(sys.stdin)))'
)
curl -v -X POST --data-raw "${query_params}" "${FORGEJO_SERVICE_ROOT}/user/sign_up" > /dev/null
echo "forgejo-user-sign-up-complete";

echo "forgejo-configured";
EOF

systemctl --user daemon-reload
systemctl --user enable forge.service
systemctl --user restart forge.service
