#!/usr/bin/env bash
set -xeuo pipefail

export DEFAULT_PYTHON="$(which python)"

export GITEA_WORK_DIR="${HOME}/.local/forgejo"
export PYTHON="${PYTHON:-${DEFAULT_PYTHON}}"

"${PYTHON}" -m pip install pyyaml keyring

set +e

FORGEJO_USERNAME=$("${PYTHON}" -m keyring get "${USER}" "${USER}.forgejo.username")
if [ "x${FORGEJO_USERNAME}" = "x" ]; then
  echo "${USER}" | "${PYTHON}" -m keyring set "${USER}" "${USER}.forgejo.username"
fi

FORGEJO_EMAIL=$("${PYTHON}" -m keyring get "${USER}" "${USER}.forgejo.email")
if [ "x${FORGEJO_EMAIL}" = "x" ]; then
  git config user.email | "${PYTHON}" -m keyring set "${USER}" "${USER}.forgejo.email"
fi

FORGEJO_PASSWORD=$("${PYTHON}" -m keyring get "${USER}" "${USER}.forgejo.password")
if [ "x${FORGEJO_PASSWORD}" = "x" ]; then
  "${PYTHON}" -m keyring set "${USER}" "${USER}.forgejo.password"
fi

export FORGEJO_FQDN="git.pdxjohnny.chadig.com"
export DIRECTUS_FQDN="directus.pdxjohnny.chadig.com"

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

mkdir -p "${HOME}/.local/forgejo-install/"
export INIT_YAML_PATH="$HOME/.local/forgejo-install/init.yaml"
tee "${INIT_YAML_PATH}" <<EOF
db_type: 'sqlite3'
db_host: '127.0.0.1:3306'
db_user: 'forgejo'
db_passwd: ''
db_name: 'forgejo'
ssl_mode: 'disable'
db_schema: ''
db_path: '${GITEA_WORK_DIR}/data/forgejo.db'
app_name: '${FORGEJO_USERNAME}-forgejo'
repo_root_path: '${GITEA_WORK_DIR}/data/forgejo-repositories'
lfs_root_path: '${GITEA_WORK_DIR}/data/lfs'
run_user: '${USER}'
domain: '${FORGEJO_FQDN}'
ssh_port: '0'
http_port: '3000'
app_url: 'https://${FORGEJO_FQDN}/'
log_root_path: '${GITEA_WORK_DIR}/data/log'
enable_update_checker: 'on'
smtp_addr: ''
smtp_port: ''
smtp_from: ''
smtp_user: ''
smtp_passwd: ''
offline_mode: 'on'
disable_gravatar: 'off'
enable_open_id_sign_in: 'off'
enable_open_id_sign_up: 'off'
default_allow_create_organization: 'on'
default_enable_timetracking: 'off'
no_reply_address: 'noreply.${FORGEJO_FQDN}'
password_algorithm: 'pbkdf2_hi'
admin_name: '${FORGEJO_USERNAME}'
admin_email: '${FORGEJO_EMAIL}'
admin_passwd: '${FORGEJO_PASSWORD}'
admin_confirm_passwd: '${FORGEJO_PASSWORD}'
EOF

# TODO TODO TODO
echo TODO Disable user creation and create admin user within init.yaml
# TODO TODO TODO

export SIGN_UP_YAML_PATH="$HOME/.local/forgejo-install/sign_up.yaml"
tee "${SIGN_UP_YAML_PATH}" <<EOF
_csrf: CSRF_TOKEN
email: alice@chadig.com
password: maryisgod
retype: maryisgod
user_name: alice
EOF

touch $HOME/.local/share/systemd/user/forge.service.sh
chmod 755 $HOME/.local/share/systemd/user/forge.service.sh
tee $HOME/.local/share/systemd/user/forge.service.sh <<'EOF'
#!/usr/bin/env bash
set -xeuo pipefail

declare -a PIDS=()

new_pid() {
  PIDS[${#PIDS[@]}]="$1"
}

cleanup_pids() {
  for pid in "${PIDS[@]}"; do
    kill "${pid}"
  done
}

declare -a DOCKER_CONTAINER_IDS=()

new_docker_container_id() {
  DOCKER_CONTAINER_IDS[${#DOCKER_CONTAINER_IDS[@]}]="$1"
}

cleanup_docker_container_ids() {
  for docker_container_id in "${DOCKER_CONTAINER_IDS[@]}"; do
    docker kill "${docker_container_id}"
  done
}

cleanup() {
  set +e
  cleanup_pids
  cleanup_docker_container_ids
}

trap cleanup EXIT

export SIGN_UP_YAML_PATH="${HOME}/.local/forgejo-install/sign_up.yaml"
export INIT_YAML_PATH="${HOME}/.local/forgejo-install/init.yaml"
export GITEA_WORK_DIR="${HOME}/.local/forgejo"

EOF
tee -a $HOME/.local/share/systemd/user/forge.service.sh <<EOF
export DEFAULT_PYTHON="${DEFAULT_PYTHON}"
export FORGEJO_FQDN="${FORGEJO_FQDN}"
export DIRECTUS_FQDN="${DIRECTUS_FQDN}"
EOF

# TODO TODO TODO TODO REMOVE RM -rfv TODO TODO TODO TODO
tee -a $HOME/.local/share/systemd/user/forge.service.sh <<'EOF'
rm -rfv \
  "${GITEA_WORK_DIR}" \
  "${HOME}/.local/directus.sqlite3" \
  "${HOME}/.local/directus_admin_role_id.txt"

export PYTHON="${PYTHON:-${DEFAULT_PYTHON}}"

referesh_role_id() {
  export DIRECTUS_ADMIN_ROLE_ID=$(echo 'SELECT id from directus_roles;' \
                                  | sqlite3 ${HOME}/.local/directus.sqlite3 2>&1 \
                                  | tee ${HOME}/.local/directus_admin_role_id.txt)
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

forgejo web &
FORGEJO_PID=$!
new_pid "${FORGEJO_PID}"

ssh -nNT -R 127.0.0.1:3000:0.0.0.0:3000 alice@scitt.unstable.chadig.com &
FORGEJO_SSH_TUNNEL_PID=$!
new_pid "${FORGEJO_SSH_TUNNEL_PID}"
ssh -nNT -R 127.0.0.1:8055:0.0.0.0:8055 alice@scitt.unstable.chadig.com &
DIRECTUS_SSH_TUNNEL_PID=$!
new_pid "${DIRECTUS_SSH_TUNNEL_PID}"

echo "awaiting-forgejo";

check_forgejo_initialized_and_running() {
  STATUS_CODE=$(curl -vI "https://${FORGEJO_FQDN}" 2>/dev/null | head -n 1 | cut -d$' ' -f2)
  if [ "x${STATUS_CODE}" = "x200" ]; then
    return 1
  elif [ "x${STATUS_CODE}" = "x405" ]; then
    echo "checking-if-forgejo-need-first-time-init";
    query_params=$("${PYTHON}" -c 'import sys, urllib.parse, yaml; print(urllib.parse.urlencode(yaml.safe_load(sys.stdin)))' < "${INIT_YAML_PATH}");
    curl -v -X POST --data-raw "${query_params}" "https://${FORGEJO_FQDN}";
    # curl -v -X POST --data-raw "${query_params}" "https://${FORGEJO_FQDN}" > /dev/null;
    echo "forgejo-first-time-init-complete";
    return 0
  fi
  return 0
}

set +e
check_forgejo_initialized_and_running
forgejo_initialized_and_running=$?
while [ "x${forgejo_initialized_and_running}" = "x0" ]; do
  sleep 0.1
  check_forgejo_initialized_and_running
  forgejo_initialized_and_running=$?
done
set -e

echo TODO Configure openid client_id and client_secret

# https://docs.gitea.com/next/development/api-usage#generating-and-listing-api-tokens
# curl -H "X-Gitea-OTP: 123456" --url https://yourusername:yourpassword@gitea.your.host/api/v1/users/yourusername/tokens
#
# curl -H "X-Gitea-OTP: 123456" --url https://yourusername:yourpassword@gitea.your.host/api/v1/users/yourusername/tokens

wait_for_and_populate_directus_admin_role_id_txt &

DIRECTUS_CONTAINER_ID=$(docker run \
  --detach \
  -p 8055:8055 \
  -e PUBLIC_URL="https://${DIRECTUS_FQDN}" \
  -e AUTH_DISABLE_DEFAULT=true \
  -e AUTH_PROVIDERS="forgejo" \
  -e AUTH_FORGEJO_DRIVER="openid" \
  -e AUTH_FORGEJO_CLIENT_ID="$("${PYTHON}" -m keyring get directus auth.forgejo.client_id)" \
  -e AUTH_FORGEJO_CLIENT_SECRET="$("${PYTHON}" -m keyring get directus auth.forgejo.client_secret)" \
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
new_docker_container_id "${DIRECTUS_CONTAINER_ID}"

tail -F /dev/null
EOF

systemctl --user daemon-reload
systemctl --user enable forge.service
systemctl --user restart forge.service
