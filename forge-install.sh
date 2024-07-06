#!/usr/bin/env bash
set -xeuo pipefail

export DEFAULT_PYTHON="$(which python)"
export INSTALL_WORK_DIR="${HOME}/.local/forgejo-install"
export GITEA_WORK_DIR="${HOME}/.local/forgejo"
export PYTHON="${PYTHON:-${DEFAULT_PYTHON}}"

if [ ! -f "${INSTALL_WORK_DIR}/.venv/bin/activate" ]; then
  "${PYTHON}" -m venv "${INSTALL_WORK_DIR}/.venv"
  . "${INSTALL_WORK_DIR}/.venv/bin/activate"
  python -m pip install pyyaml keyring beautifulsoup4
fi
. "${INSTALL_WORK_DIR}/.venv/bin/activate"

FORGEJO_USERNAME=$(python -m keyring get "${USER}" "${USER}.forgejo.username")
if [ "x${FORGEJO_USERNAME}" = "x" ]; then
  echo "${USER}" | python -m keyring set "${USER}" "${USER}.forgejo.username"
fi

FORGEJO_EMAIL=$(python -m keyring get "${USER}" "${USER}.forgejo.email")
if [ "x${FORGEJO_EMAIL}" = "x" ]; then
  git config user.email | python -m keyring set "${USER}" "${USER}.forgejo.email"
fi

FORGEJO_PASSWORD=$(python -m keyring get "${USER}" "${USER}.forgejo.password")
if [ "x${FORGEJO_PASSWORD}" = "x" ]; then
  python -m keyring set "${USER}" "${USER}.forgejo.password"
fi

export SSH_USER="${SSH_USER:-${USER}}"
export ROOT_IN_TCB_FQDN="${ROOT_IN_TCB_FQDN:-localhost}"
export ROOT_OUT_TCB_FQDN="${ROOT_OUT_TCB_FQDN:-localhost}"
# TODO scitt.unstable. should be something like caddy.admin.
export SSH_HOST="${SSH_HOST:-scitt.unstable.${ROOT_IN_TCB_FQDN}}"
export SSH_USER_AT_HOST="${SSH_USER}@${SSH_HOST}"
export SSH_WORK_DIR="/home/${SSH_USER}"
export FORGEJO_FQDN="git.${USER}.${ROOT_IN_TCB_FQDN}"
export DIRECTUS_FQDN="directus.${USER}.${ROOT_IN_TCB_FQDN}"

mkdir -p $HOME/.local/share/systemd/user

tee $HOME/.local/share/systemd/user/forge.service <<'EOF'
[Unit]
Description=Secure Softare Forge
[Service]
Type=simple
TimeoutStartSec=0
ExecStart=bash -c "exec ${HOME}/.local/share/systemd/user/forge.service.sh"
Environment=VIRTUAL_ENV=%h/.local/forgejo-install/.venv
Environment=SSH_USER=%u
Environment=ROOT_IN_TCB_FQDN=localhost
Environment=ROOT_OUT_TCB_FQDN=localhost
[Install]
WantedBy=default.target
EOF

mkdir -p "${HOME}/.local/forgejo-install/"
export INIT_COMPLETE_JSON_PATH="${HOME}/.local/forgejo-install/init-complete.json"
export INIT_YAML_PATH="${HOME}/.local/forgejo-install/init.yaml"
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

export FORGEJO_COOKIE_JAR_PATH="${HOME}/.local/forgejo-install/curl-cookie-jar"
export LOGIN_YAML_PATH="${HOME}/.local/forgejo-install/login.yaml"
tee "${LOGIN_YAML_PATH}" <<EOF
_csrf: CSRF_TOKEN
user_name: '${FORGEJO_USERNAME}'
password: '${FORGEJO_PASSWORD}'
remember: 'on'
EOF

export NEW_OAUTH2_APPLICATION_YAML_PATH="${HOME}/.local/forgejo-install/directus_oauth2_application.yaml"
tee "${NEW_OAUTH2_APPLICATION_YAML_PATH}" <<EOF
name: 'Directus'
confidential_client: true
redirect_uris:
- 'https://${DIRECTUS_FQDN}/auth/login/forgejo/callback'
EOF

touch $HOME/.local/share/systemd/user/forge.service.sh
chmod 755 $HOME/.local/share/systemd/user/forge.service.sh
tee $HOME/.local/share/systemd/user/forge.service.sh <<'EOF'
#!/usr/bin/env bash
set -xeuo pipefail

declare -a TEMPDIRS=()

new_tempdir() {
  tempdir=$(mktemp -d)
  TEMPDIRS[${#TEMPDIRS[@]}]="${tempdir}"
  echo "${tempdir}"
}

cleanup_tempdirs() {
  for tempdir in "${TEMPDIRS[@]}"; do
    rm -rf "${tempdir}"
  done
}

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

export INSTALL_WORK_DIR="${HOME}/.local/forgejo-install"
. "${INSTALL_WORK_DIR}/.venv/bin/activate"
export FORGEJO_COOKIE_JAR_PATH="${HOME}/.local/forgejo-install/curl-cookie-jar"
export LOGIN_YAML_PATH="${HOME}/.local/forgejo-install/login.yaml"
export INIT_COMPLETE_JSON_PATH="${HOME}/.local/forgejo-install/init-complete.json"
export NEW_OAUTH2_APPLICATION_YAML_PATH="${HOME}/.local/forgejo-install/directus_oauth2_application.yaml"
export INIT_YAML_PATH="${HOME}/.local/forgejo-install/init.yaml"
export GITEA_WORK_DIR="${HOME}/.local/forgejo"

cleanup_files() {
  return
  rm -fv "${INIT_YAML_PATH}" "${NEW_OAUTH2_APPLICATION_YAML_PATH}" "${FORGEJO_COOKIE_JAR_PATH}" "${LOGIN_YAML_PATH}"
}

cleanup() {
  set +e
  cleanup_files
  cleanup_tempdirs
  cleanup_pids
  cleanup_docker_container_ids
}

trap cleanup EXIT

export SSH_USER="${SSH_USER:-${USER}}"
export ROOT_IN_TCB_FQDN="${ROOT_IN_TCB_FQDN:-localhost}"
export ROOT_OUT_TCB_FQDN="${ROOT_OUT_TCB_FQDN:-localhost}"
# TODO scitt.unstable. should be something like caddy.admin.
export SSH_HOST="${SSH_HOST:-scitt.unstable.${ROOT_IN_TCB_FQDN}}"
export SSH_USER_AT_HOST="${SSH_USER}@${SSH_HOST}"
export SSH_WORK_DIR="/home/${SSH_USER}"
export FORGEJO_FQDN="git.${USER}.${ROOT_IN_TCB_FQDN}"
export DIRECTUS_FQDN="directus.${USER}.${ROOT_IN_TCB_FQDN}"

# TODO TODO TODO TODO Document INIT_COMPLETE_JSON_PATH to reset_state TODO TODO
tee -a $HOME/.local/share/systemd/user/forge.service.sh <<'EOF'
export CADDY_USE_SSH=1
if [[ "x${SSH_USER}" = "x${USER}" ]] && [[ "x${ROOT_IN_TCB_FQDN}" = "xlocalhost" ]] && [[ "x${ROOT_OUT_TCB_FQDN}" = "xlocalhost" ]]; then
  export CADDY_USE_SSH=0
fi

tee $HOME/.local/share/systemd/user/forge.service.Caddyfile <<CADDY_EOF
{
  admin "unix/${SSH_WORK_DIR}/caddy.admin.sock" {
    origins localhost
  }
}
CADDY_EOF

reset_state() {
  rm -rfv \
    "${GITEA_WORK_DIR}" \
    "${HOME}/.local/directus.sqlite3" \
    "${HOME}/.local/directus_admin_role_id.txt"
}

if [ ! -f "${INIT_COMPLETE_JSON_PATH}" ]; then
  reset_state
fi

referesh_generated_admin_id() {
  export DIRECTUS_ADMIN_ID=$(echo 'SELECT id FROM directus_users WHERE email="admin@example.com";' \
                             | sqlite3 ${HOME}/.local/directus.sqlite3 2> >(grep -v 'database is locked' | grep -v directus_users >&2))
}

referesh_role_id() {
  export DIRECTUS_ADMIN_ROLE_ID=$(echo 'SELECT id from directus_roles;' \
                                  | sqlite3 ${HOME}/.local/directus.sqlite3 2> >(grep -v 'database is locked' | grep -v directus_roles >&2) \
                                  | tee ${HOME}/.local/directus_admin_role_id.txt)
}

wait_for_and_populate_directus_admin_role_id_txt() {
  set +x
  referesh_role_id
  while [ "x" = "x${DIRECTUS_ADMIN_ROLE_ID}" ]; do
    sleep 0.01
    referesh_role_id
  done
  referesh_generated_admin_id
  while [ "x" = "x${DIRECTUS_ADMIN_ID}" ]; do
    sleep 0.01
    referesh_generated_admin_id
  done
  while [ "x" != "x${DIRECTUS_ADMIN_ID}" ]; do
    echo 'DELETE FROM directus_users WHERE email="admin@example.com";' | sqlite3 "${HOME}/.local/directus.sqlite3"
    referesh_generated_admin_id
  done
  set -x
}

find_listening_ports() {
  # Check if PID is provided
  if [ -z "$1" ]; then
    echo "Usage: find_listening_ports <PID>" 1>&2
    return 1
  fi

  PID=$1

  # Check if the process with the given PID exists
  if ! ps -p $PID > /dev/null 2>&1; then
    echo "Process with PID $PID does not exist." 1>&2
    return 1
  fi

  # Find listening TCP ports for the given PID using ss
  LISTENING_PORTS=$(ss -ltnp 2>/dev/null | grep "pid=$PID")

  if [ -z "$LISTENING_PORTS" ]; then
    echo "Process with PID $PID not listening on any ports." 1>&2
    return 1
  fi

  echo "$LISTENING_PORTS" | awk '{print $4}' | awk -F':' '{print $NF}'
}
#!/bin/bash

# Function to retrieve route ID by FQDN
get_route_id() {
    local socket_path=$1
    local fqdn=$2

    local route_id=$(curl -fs --unix-socket $socket_path http://localhost/config/ | jq -r --arg fqdn "$fqdn" '.apps.http.servers.srv0.routes[] | select(.match[0].host[0] == $fqdn) | .id')
    echo "$route_id"
}

# Function to create or update a route in Caddy
create_or_update_route() {
    local socket_path=$1
    local fqdn=$2
    local target=$3

    export config=$(curl -f --unix-socket $socket_path "http://localhost/config/")
    echo -e "$fqdn {\n    reverse_proxy $target\n}\n" \
    | curl --unix-socket $socket_path http://localhost/adapt \
         -H "Content-Type: text/caddyfile" \
        --data-binary @- \
    | tee /tmp/1 \
    | jq '.result * (env.config | fromjson)' \
    | tee /tmp/2 \
    | curl -f -X POST --unix-socket $socket_path "http://localhost/config/" \
         -H "Content-Type: application/json" \
         -d @-
}

if [[ "x${CADDY_USE_SSH}" = "x0" ]]; then
  export CURL_CA_BUNDLE="${HOME}/.local/share/caddy/pki/authorities/local/root.crt"
  caddy run --config "${HOME}/.local/share/systemd/user/forge.service.Caddyfile" &
  CADDY_PID=$!
  new_pid "${CADDY_PID}"
fi

export CADDY_ADMIN_SOCKET="${SSH_WORK_DIR}/caddy.admin.sock"
if [[ "x${CADDY_USE_SSH}" = "x1" ]]; then
  CADDY_ADMIN_SOCK_DIR_PATH=$(new_tempdir)
  export CADDY_ADMIN_SOCKET_OVER_SSH="${CADDY_ADMIN_SOCK_DIR_PATH}/caddy.admin.sock"
  ssh -o StrictHostKeyChecking=no -nNT -L "${CADDY_ADMIN_SOCKET_OVER_SSH}:${CADDY_ADMIN_SOCKET}" "${SSH_USER_AT_HOST}" &
  CADDY_ADMIN_SOCK_SSH_TUNNEL_PID=$!
  new_pid "${CADDY_ADMIN_SOCK_SSH_TUNNEL_PID}"
  export CADDY_ADMIN_SOCKET="${CADDY_ADMIN_SOCKET_OVER_SSH}"
fi


forgejo web --port 0 &
FORGEJO_PID=$!
new_pid "${FORGEJO_PID}"
set +x
until find_listening_ports "${FORGEJO_PID}"; do sleep 0.01; done
set -x
FORGEJO_PORT=$(find_listening_ports "${FORGEJO_PID}")

export FORGEJO_CADDY_TARGET="127.0.0.1:${FORGEJO_PORT}"
if [[ "x${CADDY_USE_SSH}" = "x1" ]]; then
  export FORGEJO_SOCK="${SSH_WORK_DIR}/${FORGEJO_FQDN}.sock"
  ssh -o StrictHostKeyChecking=no -nT "${SSH_USER_AT_HOST}" rm -fv "${FORGEJO_SOCK}"
  ssh -o StrictHostKeyChecking=no -nNT -R "${FORGEJO_SOCK}:${FORGEJO_CADDY_TARGET}" "${SSH_USER_AT_HOST}" &
  FORGEJO_SSH_TUNNEL_PID=$!
  new_pid "${FORGEJO_SSH_TUNNEL_PID}"
  export FORGEJO_CADDY_TARGET="unix/${FORGEJO_SOCK}"
else
  export FORGEJO_CADDY_TARGET="http://${FORGEJO_CADDY_TARGET}"
fi
create_or_update_route "${CADDY_ADMIN_SOCKET}" "${FORGEJO_FQDN}" "${FORGEJO_CADDY_TARGET}"

echo "awaiting-forgejo";

check_forgejo_initialized_and_running() {
  curl -vI "https://${FORGEJO_FQDN}"
  STATUS_CODE=$(curl -vI "https://${FORGEJO_FQDN}" 2>/dev/null | head -n 1 | cut -d$' ' -f2)
  if [ "x${STATUS_CODE}" = "x200" ]; then
    return 1
  elif [ "x${STATUS_CODE}" = "x405" ]; then
    echo "checking-if-forgejo-need-first-time-init";
    query_params=$(python -c 'import sys, urllib.parse, yaml; print(urllib.parse.urlencode(yaml.safe_load(sys.stdin)))' < "${INIT_YAML_PATH}");
    curl -v -X POST --data-raw "${query_params}" "https://${FORGEJO_FQDN}" 1>/dev/null;

    FORGEJO_USERNAME=$(python -m keyring get "${USER}" "${USER}.forgejo.username")
    FORGEJO_EMAIL=$(python -m keyring get "${USER}" "${USER}.forgejo.email")
    FORGEJO_PASSWORD=$(python -m keyring get "${USER}" "${USER}.forgejo.password")

    # https://docs.gitea.com/next/development/api-usage#generating-and-listing-api-tokens
    # curl -H "X-Gitea-OTP: 123456" --url https://yourusername:yourpassword@gitea.your.host/api/v1/users/yourusername/tokens
    get_forgejo_token() {
      curl -sf -u "${FORGEJO_USERNAME}:${FORGEJO_PASSWORD}" -H "Content-Type: application/json" -d '{"name": "forgejo-install-auth-oidc-directus", "scopes": ["write:admin"]}'  "https://${FORGEJO_FQDN}/api/v1/users/${FORGEJO_USERNAME}/tokens" | jq -r '.sha1'
    }
    FORGEJO_TOKEN=$(get_forgejo_token)
    while [ "x${FORGEJO_TOKEN}" = "x" ]; do
      sleep 0.1
      FORGEJO_TOKEN=$(get_forgejo_token)
    done

    data=$(
      cat "${NEW_OAUTH2_APPLICATION_YAML_PATH}" \
        | python -c 'import sys, json, yaml; print(json.dumps(yaml.safe_load(sys.stdin)))'
    )
    export RESPONSE=$(curl -vf -u "${FORGEJO_USERNAME}:${FORGEJO_PASSWORD}" -H "Content-Type: application/json" --data "${data}" "https://${FORGEJO_FQDN}/api/v1/user/applications/oauth2" | jq -c)
    jq -rn 'env.RESPONSE | fromjson | .client_id' | python -m keyring set ${USER} ${USER}.directus.auth.forgejo.client_id
    jq -rn 'env.RESPONSE | fromjson | .client_secret' | python -m keyring set ${USER} ${USER}.directus.auth.forgejo.client_secret
    unset RESPONSE

    # TODO Add Application ID, etc. non secrets to init-complete.yaml
    touch "${INIT_COMPLETE_JSON_PATH}"
  fi
  return 0
}

test -f "${INIT_YAML_PATH}"

set +e
check_forgejo_initialized_and_running
forgejo_initialized_and_running=$?
while [ "x${forgejo_initialized_and_running}" = "x0" ]; do
  sleep 0.1
  check_forgejo_initialized_and_running
  forgejo_initialized_and_running=$?
done
set -e
echo "forgejo-first-time-init-complete";
cleanup_files

echo TODO Configure openid client_id and client_secret

wait_for_and_populate_directus_admin_role_id_txt &

DIRECTUS_CONTAINER_ID=$(docker run \
  --detach \
  -e PUBLIC_URL="https://${DIRECTUS_FQDN}" \
  -e TELEMETRY=false \
  -e WEBSOCKETS_ENABLED=true \
  -e WEBSOCKETS_REST_AUTH=strict \
  -e WEBSOCKETS_GRAPHQL_AUTH=strict \
  -e AUTH_DISABLE_DEFAULT=true \
  -e AUTH_PROVIDERS="forgejo" \
  -e AUTH_FORGEJO_DRIVER="openid" \
  -e AUTH_FORGEJO_CLIENT_ID="$(python -m keyring get ${USER} ${USER}.directus.auth.forgejo.client_id)" \
  -e AUTH_FORGEJO_CLIENT_SECRET="$(python -m keyring get ${USER} ${USER}.directus.auth.forgejo.client_secret)" \
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
  'set -x && node cli.js bootstrap && while [ "x$(cat admin_role_id.txt)" = "x" ]; do sleep 0.01; done && export AUTH_FORGEJO_DEFAULT_ROLE_ID=$(cat admin_role_id.txt) && pm2-runtime start ecosystem.config.cjs')
new_docker_container_id "${DIRECTUS_CONTAINER_ID}"

docker logs -f "${DIRECTUS_CONTAINER_ID}" &
DIRECTUS_CONTAINER_LOGS_PID=$!
new_pid "${DIRECTUS_CONTAINER_LOGS_PID}"

DIRECTUS_CONTAINER_IP=$(docker inspect --format json "${DIRECTUS_CONTAINER_ID}" | jq -r '.[0].NetworkSettings.IPAddress')

export DIRECTUS_CADDY_TARGET="${DIRECTUS_CONTAINER_IP}:8055"
if [[ "x${CADDY_USE_SSH}" = "x1" ]]; then
  export DIRECTUS_SOCK="${SSH_WORK_DIR}/${DIRECTUS_FQDN}.sock"
  ssh -o StrictHostKeyChecking=no -nT "${SSH_USER_AT_HOST}" rm -fv "${DIRECTUS_SOCK}"
  ssh -o StrictHostKeyChecking=no -nNT -R "${DIRECTUS_SOCK}:${DIRECTUS_CADDY_TARGET}" "${SSH_USER_AT_HOST}" &
  DIRECTUS_SSH_TUNNEL_PID=$!
  new_pid "${DIRECTUS_SSH_TUNNEL_PID}"
  export DIRECTUS_CADDY_TARGET="unix/${DIRECTUS_SOCK}"
else
  export DIRECTUS_CADDY_TARGET="http://${DIRECTUS_CADDY_TARGET}"
fi
create_or_update_route "${CADDY_ADMIN_SOCKET}" "${DIRECTUS_FQDN}" "${DIRECTUS_CADDY_TARGET}"

if [[ "x${CADDY_USE_SSH}" = "x1" ]]; then
  kill "${CADDY_ADMIN_SOCK_SSH_TUNNEL_PID}"
fi

tail -F /dev/null
EOF

systemctl --user daemon-reload
systemctl --user enable forge.service
systemctl --user restart forge.service
