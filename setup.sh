#!/bin/bash

set -euo pipefail

# https://stackoverflow.com/a/28085062/18954618
: "${CI:=false}"
: "${WITH_REDIS:=false}"
: "${SUDO_USER:=""}"

NO_COLOR=''
RED=''
CYAN=''
GREEN=''

# Check if terminal supports colors https://unix.stackexchange.com/a/10065/642181
if [ -t 1 ]; then
    total_colors=$(tput colors)
    if [[ -n "$total_colors" && $total_colors -ge 8 ]]; then
        # https://stackoverflow.com/a/28938235/18954618
        NO_COLOR='\033[0m'
        RED='\033[0;31m'
        CYAN='\033[0;36m'
        GREEN='\033[0;32m'
    fi
fi

error_log() { echo -e "${RED}ERROR: $1${NO_COLOR}"; }
info_log() { echo -e "${CYAN}INFO: $1${NO_COLOR}"; }
error_exit() {
    error_log "$*"
    exit 1
}

# https://stackoverflow.com/a/18216122/18954618
if [ "$EUID" -ne 0 ]; then error_exit "Please run this script as root user"; fi

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Self-host Supabase with nginx/caddy and authelia 2FA with just ONE bash script."
    echo ""
    echo "Options:"
    echo "  -h, --help           Show this help message and exit"
    echo "  --proxy PROXY        Set the reverse proxy to use (nginx or caddy). Default: caddy"
    echo "  --with-authelia      Enable or disable Authelia 2FA support"
    echo ""
    echo "Examples:"
    echo "  $0 --proxy nginx --with-authelia    # Set up Supabase with nginx and Authelia 2FA"
    echo "  $0 --proxy caddy                    # Set up Supabase with caddy and no 2FA"
    echo ""
    echo "For more information, visit the project repository:"
    echo "https://github.com/singh-inder/supabase-automated-self-host"
}

has_argument() {
    [[ ("$1" == *=* && -n ${1#*=}) || (-n "$2" && "$2" != -*) ]]
}

extract_argument() { echo "${2:-${1#*=}}"; }

with_authelia=false
proxy="caddy"

# https://medium.com/@wujido20/handling-flags-in-bash-scripts-4b06b4d0ed04
while [ $# -gt 0 ]; do
    case "$1" in
    -h | --help)
        usage
        exit 0
        ;;

    --with-authelia)
        with_authelia=true
        ;;

    --proxy)
        if has_argument "$@"; then
            proxy="$(extract_argument "$@")"
            shift
        fi
        ;;

    *)
        echo -e "ERROR: ${RED}Invalid option:${NO_COLOR} $1" >&2
        usage
        exit 1
        ;;
    esac
    shift
done

if [[ "$proxy" != "caddy" && "$proxy" != "nginx" ]]; then
    error_exit "proxy can only be caddy or nginx"
fi

info_log "Configuration Summary"
echo -e "  ${GREEN}Proxy:${NO_COLOR} ${proxy}"
echo -e "  ${GREEN}Authelia 2FA:${NO_COLOR} ${with_authelia}"

detect_arch() {
    case $(uname -m) in
    x86_64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    armv7l) echo "arm" ;;
    i686 | i386) echo "386" ;;
    *) echo "err" ;;
    esac
}

#https://stackoverflow.com/a/18434831/18954618
detect_os() {
    case $(uname | tr '[:upper:]' '[:lower:]') in
    linux*) echo "linux" ;;
    # darwin*) echo "darwin" ;;
    *) echo "err" ;;
    esac
}

os="$(detect_os)"
arch="$(detect_arch)"

if [[ "$os" == "err" ]]; then error_exit "This script only supports linux os"; fi
if [[ "$arch" == "err" ]]; then error_exit "Unsupported cpu architecture"; fi

packages=(curl wget jq openssl git)

# set -e doesn't work if any command is part of an if statement. package installation errors have to be checked https://stackoverflow.com/a/821419/18954618
# https://unix.stackexchange.com/a/571192/642181
if [ -x "$(command -v apt-get)" ]; then
    apt-get update && apt-get install -y "${packages[@]}" apache2-utils

elif [ -x "$(command -v apk)" ]; then
    apk update && apk add --no-cache "${packages[@]}" apache2-utils

elif [ -x "$(command -v dnf)" ]; then
    dnf makecache && dnf install -y "${packages[@]}" httpd-tools

elif [ -x "$(command -v zypper)" ]; then
    zypper refresh && zypper install "${packages[@]}" apache2-utils

elif [ -x "$(command -v pacman)" ]; then
    pacman -Syu --noconfirm "${packages[@]}" apache

elif [ -x "$(command -v pkg)" ]; then
    pkg update && pkg install -y "${packages[@]}" apache24

elif [[ -x "$(command -v brew)" && -n "$SUDO_USER" ]]; then
    # brew doesn't allow installation with sudo privileges, thats why have to run script as user who initiated this script with sudo privileges
    sudo -u "$SUDO_USER" brew install "${packages[@]}" httpd
else
    # diff between array expansion with "@" and "*" https://linuxsimply.com/bash-scripting-tutorial/expansion/array-expansion/
    error_exit "Failed to install packages. Package manager not found.\nSupported package managers: apt, apk, dnf, zypper, pacman, pkg, brew"
fi

if [ $? -ne 0 ]; then error_exit "Failed to install packages."; fi

githubAc="https://github.com/singh-inder"
repoUrl="$githubAc/supabase-automated-self-host"
directory="$(basename "$repoUrl")"

if [ -d "$directory" ]; then
    info_log "$directory directory present, skipping git clone"
else
    git clone --depth=1 "$repoUrl" "$directory"
fi

if ! cd "$directory"/docker; then error_exit "Unable to access $directory/docker directory"; fi
if [ ! -f ".env.example" ]; then error_exit ".env.example file not found. Exiting!"; fi

download_binary() { wget "$1" -O "$2" &>/dev/null && chmod +x "$2" &>/dev/null; }
downloadLocation="/usr/local/bin"

if [ ! -x "$downloadLocation"/url-parser ]; then
    info_log "Downloading url-parser from $githubAc/url-parser and saving in $downloadLocation"
    download_binary "$githubAc"/url-parser/releases/download/v1.1.0/url-parser-"$os"-"$arch" "$downloadLocation"/url-parser
fi

if [ ! -x "$downloadLocation"/yq ]; then
    info_log "Downloading yq from https://github.com/mikefarah/yq and saving in $downloadLocation"
    download_binary https://github.com/mikefarah/yq/releases/download/v4.45.4/yq_"$os"_"$arch" "$downloadLocation"/yq
fi

echo -e "---------------------------------------------------------------------------\n"

format_prompt() { echo -e "${GREEN}$1${NO_COLOR}"; }

confirmation_prompt() {
    local variable_to_update_name="$1"
    local answer=""
    read -rp "$(format_prompt "$2")" answer

    # converts input to lowercase
    case "${answer,,}" in
    y | yes)
        answer=true
        ;;
    n | no)
        answer=false
        ;;
    *)
        error_log "Please answer yes or no\n"
        answer=""
        ;;
    esac

    # Use eval to dynamically assign the new value to the variable name. This indirectly updates the variable in the caller's scope.
    if [ -n "$answer" ]; then eval "$variable_to_update_name=$answer"; fi
}

domain=""
while [ -z "$domain" ]; do
    if [ "$CI" == true ]; then
        domain="https://supabase.example.com"
    else
        read -rp "$(format_prompt "Enter your domain:") " domain
    fi

    if ! protocol="$(url-parser --url "$domain" --get scheme 2>/dev/null)"; then
        error_log "Couldn't extract protocol. Please check the url you entered.\n"
        domain=""
        continue
    fi

    if ! host="$(url-parser --url "$domain" --get host 2>/dev/null)"; then
        error_log "Couldn't extract url host. Please check the url you entered.\n"
        domain=""
        continue
    fi

    if [[ "$with_authelia" == true ]]; then
        # cookies.authelia_url needs to be https https://www.authelia.com/configuration/session/introduction/#authelia_url
        if [[ "$protocol" != "https" ]]; then
            error_log "As you've enabled --with-authelia flag, url protocol needs to https"
            domain=""
        else
            if
                ! registered_domain="$(url-parser --url "$domain" --get registeredDomain 2>/dev/null)" || [ -z "$registered_domain" ] ||
                    [ "$registered_domain" = "." ]
            then
                error_log "Couldn't extract root domain. Please check the url you entered.\n"
                domain=""
            fi
        fi

    elif [[ "$protocol" != "http" && "$protocol" != "https" ]]; then
        error_log "Url protocol must be http or https\n"
        domain=""
    fi
done

username=""
if [[ "$CI" == true ]]; then username="inder"; fi

while [ -z "$username" ]; do
    read -rp "$(format_prompt "Enter username:") " username

    # https://stackoverflow.com/questions/18041761/bash-need-to-test-for-alphanumeric-string
    if [[ ! "$username" =~ ^[a-zA-Z0-9]+$ ]]; then
        error_log "Only alphabets and numbers are allowed"
        username=""
    fi
    # read command automatically trims leading & trailing whitespace. No need to handle it separately
done

password=""
confirmPassword=""

if [[ "$CI" == true ]]; then
    password="password"
    confirmPassword="password"
fi

while [[ -z "$password" || "$password" != "$confirmPassword" ]]; do
    read -s -rp "$(format_prompt "Enter password(password is hidden):") " password
    echo
    read -s -rp "$(format_prompt "Confirm password:") " confirmPassword
    echo

    if [[ "$password" != "$confirmPassword" ]]; then
        error_log "Password mismatch. Please try again!\n"
    fi
done

autoConfirm=""
if [[ "$CI" == true ]]; then autoConfirm="false"; fi

while [ -z "$autoConfirm" ]; do
    confirmation_prompt autoConfirm "Do you want to send confirmation emails to register users? If yes, you'll have to setup your own SMTP server [y/n]: "
    if [[ "$autoConfirm" == true ]]; then
        autoConfirm="false"
    elif [[ "$autoConfirm" == false ]]; then
        autoConfirm="true"
    fi
done

# If with_authelia, then additionally ask for email and display name
if [[ "$with_authelia" == true ]]; then
    email=""
    display_name=""
    setup_redis=""

    if [[ "$CI" == true ]]; then
        email="johndoe@gmail.com"
        display_name="Inder Singh"
        if [[ "$WITH_REDIS" == true ]]; then setup_redis=true; fi
    fi

    while [ -z "$email" ]; do
        read -rp "$(format_prompt "Enter your email for Authelia:") " email

        # split email string on @ symbol
        IFS="@" read -r before_at after_at <<<"$email"

        if [[ -z "$before_at" || -z "$after_at" ]]; then
            error_log "Invalid email"
            email=""
        fi
    done

    while [ -z "$display_name" ]; do
        read -rp "$(format_prompt "Enter Display Name:") " display_name

        if [[ ! "$display_name" =~ ^[a-zA-Z0-9[:space:]]+$ ]]; then
            error_log "Only alphabets, numbers and spaces are allowed"
            display_name=""
        fi
    done

    while [[ "$CI" == false && -z "$setup_redis" ]]; do
        confirmation_prompt setup_redis "Do you want to setup redis with authelia? [y/n]: "
    done
fi

info_log "Finishing..."

# in caddy basic_auth, hashed password is loaded in memory
# in nginx basic_auth, websites slows down a lot if bcrypt rounds number is high as the hashed password file is checked again and again on every request.
# This is only applicable when using basic_auth, not with authelia
bcryptRounds=12
if [[ "$proxy" == "nginx" && "$with_authelia" == false ]]; then bcryptRounds=6; fi

# https://www.baeldung.com/linux/bcrypt-hash#using-htpasswd
password=$(htpasswd -bnBC "$bcryptRounds" "" "$password" | cut -d : -f 2)

gen_hex() { openssl rand -hex "$1"; }

jwt_secret="$(gen_hex 20)"

base64_url_encode() { openssl enc -base64 -A | tr '+/' '-_' | tr -d '='; }

header='{"typ": "JWT","alg": "HS256"}'
header_base64=$(printf %s "$header" | base64_url_encode)
# iat and exp for both tokens has to be same thats why initializing here
iat=$(date +%s)
exp=$(("$iat" + 5 * 3600 * 24 * 365)) # 5 years expiry

gen_token() {
    local payload=$(
        echo "$1" | jq --arg jq_iat "$iat" --arg jq_exp "$exp" '.iat=($jq_iat | tonumber) | .exp=($jq_exp | tonumber)'
    )

    local payload_base64=$(printf %s "$payload" | base64_url_encode)

    local signed_content="${header_base64}.${payload_base64}"

    local signature=$(printf %s "$signed_content" | openssl dgst -binary -sha256 -hmac "$jwt_secret" | base64_url_encode)

    printf '%s' "${signed_content}.${signature}"
}

anon_payload='{"role": "anon", "iss": "supabase"}'
anon_token=$(gen_token "$anon_payload")

service_role_payload='{"role": "service_role", "iss": "supabase"}'
service_role_token=$(gen_token "$service_role_payload")

sed -e "3d" \
    -e "s|POSTGRES_PASSWORD.*|POSTGRES_PASSWORD=$(gen_hex 16)|" \
    -e "s|JWT_SECRET.*|JWT_SECRET=$jwt_secret|" \
    -e "s|ANON_KEY.*|ANON_KEY=$anon_token|" \
    -e "s|SERVICE_ROLE_KEY.*|SERVICE_ROLE_KEY=$service_role_token|" \
    -e "s|DASHBOARD_PASSWORD.*|DASHBOARD_PASSWORD=not_being_used|" \
    -e "s|SECRET_KEY_BASE.*|SECRET_KEY_BASE=$(gen_hex 32)|" \
    -e "s|VAULT_ENC_KEY.*|VAULT_ENC_KEY=$(gen_hex 16)|" \
    -e "s|API_EXTERNAL_URL.*|API_EXTERNAL_URL=$domain/goapi|" \
    -e "s|SUPABASE_PUBLIC_URL.*|SUPABASE_PUBLIC_URL=$domain|" \
    -e "s|ENABLE_EMAIL_AUTOCONFIRM.*|ENABLE_EMAIL_AUTOCONFIRM=$autoConfirm|" \
    -e "s|S3_PROTOCOL_ACCESS_KEY_ID.*|S3_PROTOCOL_ACCESS_KEY_ID=$(gen_hex 16)|" \
    -e "s|S3_PROTOCOL_ACCESS_KEY_SECRET.*|S3_PROTOCOL_ACCESS_KEY_SECRET=$(gen_hex 32)|" .env.example >.env

update_yaml_file() {
    # https://github.com/mikefarah/yq/issues/465#issuecomment-2265381565
    sed -i '/^\r\{0,1\}$/s// #BLANK_LINE/' "$2"
    yq -i "$1" "$2"
    sed -i "s/ *#BLANK_LINE//g" "$2"
}

compose_file="docker-compose.yml"
env_vars=""

update_env_vars() {
    for env_key_value in "$@"; do
        env_vars="${env_vars}\n$env_key_value"
    done
}

# START DEFINING proxy_service_yaml
proxy_service_yaml=".services.$proxy.container_name=\"$proxy-container\" |
.services.$proxy.restart=\"unless-stopped\" |
.services.$proxy.ports=[\"80:80\",\"443:443\",\"443:443/udp\"] |
.services.$proxy.depends_on.kong.condition=\"service_healthy\"
"
if [[ "$with_authelia" == true ]]; then
    proxy_service_yaml="${proxy_service_yaml} | .services.$proxy.depends_on.authelia.condition=\"service_healthy\""
fi

if [[ "$proxy" == "caddy" ]]; then
    caddy_local_volume="./volumes/caddy"
    caddyfile_local="$caddy_local_volume/Caddyfile"

    # mounted local ./volumes/caddy/snippets to this path inside container
    caddySnippetsPath="/etc/caddy/snippets"

    # BIND MOUNT VOLUMES CONFIG
    proxy_service_yaml="${proxy_service_yaml} |
                        .services.caddy.image=\"caddy:2.10.2\" |
                        .services.caddy.environment.DOMAIN=\"\${SUPABASE_PUBLIC_URL:?error}\" |
                        .services.caddy.volumes=[\"$caddyfile_local:/etc/caddy/Caddyfile\",
                                                \"$caddy_local_volume/caddy_data:/data\",
                                                \"$caddy_local_volume/caddy_config:/config\",
                                                \"$caddy_local_volume/snippets:$caddySnippetsPath\"]"
else
    update_env_vars "NGINX_SERVER_NAME=$host"
    # docker compose nginx service command directive. Passed via yq strenv
    nginx_cmd=""

    nginx_local_volume="./volumes/nginx"
    # path in local fs where nginx template file is stored
    nginx_local_template_file="$nginx_local_volume/nginx.template"

    # path inside container where template file will be mounted
    nginx_container_template_file="/etc/nginx/user_conf.d/nginx.template"

    # Pass an array of args to nginx service command directive https://stackoverflow.com/a/57821785/18954618
    # output multiline string from yq https://mikefarah.gitbook.io/yq/operators/string-operators#string-blocks-bash-and-newlines

    proxy_service_yaml="${proxy_service_yaml} |
                        .services.nginx.image=\"jonasal/nginx-certbot:6.0.1-nginx1.29.1\" |
                        .services.nginx.volumes=[\"$nginx_local_volume:/etc/nginx/user_conf.d\",\"$nginx_local_volume/letsencrypt:/etc/letsencrypt\"] |
                        .services.nginx.environment.NGINX_SERVER_NAME = \"\${NGINX_SERVER_NAME:?error}\" |
                        .services.nginx.environment.CERTBOT_EMAIL=\"your@email.org\" |
                        .services.nginx.command=[\"/bin/bash\",\"-c\",strenv(nginx_cmd)]
                       "

    if [[ "$CI" == true ]]; then
        # https://github.com/JonasAlfredsson/docker-nginx-certbot/blob/master/docs/advanced_usage.md#local-ca
        proxy_service_yaml="${proxy_service_yaml} | .services.nginx.environment.USE_LOCAL_CA=1"
    fi

    # https://www.baeldung.com/linux/nginx-config-environment-variables#4-a-common-pitfall

    printf -v nginx_cmd \
        "envsubst '\$\${NGINX_SERVER_NAME}' < %s > %s/nginx.conf \\
&& /scripts/start_nginx_certbot.sh\n" \
        "$nginx_container_template_file" "$(dirname "$nginx_container_template_file")"
fi

# HANDLE BASIC_AUTH
if [[ "$with_authelia" == false ]]; then
    update_env_vars "PROXY_AUTH_USERNAME=$username" "PROXY_AUTH_PASSWORD='$password'"

    proxy_service_yaml="${proxy_service_yaml} | 
                        .services.$proxy.environment.PROXY_AUTH_USERNAME = \"\${PROXY_AUTH_USERNAME:?error}\" |
                        .services.$proxy.environment.PROXY_AUTH_PASSWORD = \"\${PROXY_AUTH_PASSWORD:?error}\"
                        "

    if [[ "$proxy" == "nginx" ]]; then
        # path inside nginx container for storing basic_auth credentials
        nginx_pass_file="/etc/nginx/user_conf.d/supabase-self-host-users"

        printf -v nginx_cmd "echo \"\$\${PROXY_AUTH_USERNAME}:\$\${PROXY_AUTH_PASSWORD}\" >%s \\
&& %s" $nginx_pass_file "$nginx_cmd"
    fi
fi

nginx_cmd="${nginx_cmd:=""}" update_yaml_file "$proxy_service_yaml" "$compose_file"

if [[ "$with_authelia" == true ]]; then
    # Dynamically update yaml path from env https://github.com/mikefarah/yq/discussions/1253
    # https://mikefarah.gitbook.io/yq/operators/style

    # WRITE AUTHELIA users_database.yml file
    # adding disabled=false after updating style to double so that every value except disabled is double quoted
    yaml_path=".users.$username" displayName="$display_name" password="$password" email="$email" \
        yq -n 'eval(strenv(yaml_path)).displayname = strenv(displayName) |
               eval(strenv(yaml_path)).password = strenv(password) | 
               eval(strenv(yaml_path)).email = strenv(email) | 
               eval(strenv(yaml_path)).groups = ["admins","dev"] | 
               .. style="double" | 
               eval(strenv(yaml_path)).disabled = false' >./volumes/authelia/users_database.yml

    authelia_config_file_yaml='.access_control.rules[0].domain=strenv(host) | 
            .session.cookies[0].domain=strenv(registered_domain) | 
            .session.cookies[0].authelia_url=strenv(authelia_url) |
            .session.cookies[0].default_redirection_url=strenv(redirect_url)'

    server_endpoints="forward-auth"
    implementation="ForwardAuth"

    if [[ "$proxy" == "nginx" ]]; then
        server_endpoints="auth-request"
        implementation="AuthRequest"
    fi

    # auth implementation
    authelia_config_file_yaml="${authelia_config_file_yaml} | .server.endpoints.authz.$server_endpoints.implementation=\"$implementation\""

    update_env_vars "AUTHELIA_SESSION_SECRET=$(gen_hex 32)" "AUTHELIA_STORAGE_ENCRYPTION_KEY=$(gen_hex 32)" "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET=$(gen_hex 32)"

    # shellcheck disable=SC2016
    authelia_docker_service_yaml='.services.authelia.container_name = "authelia" |
       .services.authelia.image = "authelia/authelia:4.38" |
       .services.authelia.volumes = ["./volumes/authelia:/config"] |
       .services.authelia.depends_on.db.condition = "service_healthy" |
       .services.authelia.expose = [9091] |    
       .services.authelia.restart = "unless-stopped" |    
       .services.authelia.healthcheck.disable = false |
       .services.authelia.environment = {
         "AUTHELIA_STORAGE_POSTGRES_ADDRESS": "tcp://db:5432",
         "AUTHELIA_STORAGE_POSTGRES_USERNAME": "postgres",
         "AUTHELIA_STORAGE_POSTGRES_PASSWORD" : "${POSTGRES_PASSWORD}",
         "AUTHELIA_STORAGE_POSTGRES_DATABASE" : "${POSTGRES_DB}",
         "AUTHELIA_STORAGE_POSTGRES_SCHEMA" : strenv(authelia_schema),
         "AUTHELIA_SESSION_SECRET": "${AUTHELIA_SESSION_SECRET:?error}",
         "AUTHELIA_STORAGE_ENCRYPTION_KEY": "${AUTHELIA_STORAGE_ENCRYPTION_KEY:?error}",
         "AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET": "${AUTHELIA_IDENTITY_VALIDATION_RESET_PASSWORD_JWT_SECRET:?error}"
       } |       
       .services.db.environment.AUTHELIA_SCHEMA = strenv(authelia_schema) |
       .services.db.volumes += "./volumes/db/schema-authelia.sh:/docker-entrypoint-initdb.d/schema-authelia.sh"'

    if [[ "$setup_redis" == true ]]; then
        authelia_config_file_yaml="${authelia_config_file_yaml}|.session.redis.host=\"redis\" | .session.redis.port=6379"

        authelia_docker_service_yaml="${authelia_docker_service_yaml}|.services.redis.container_name=\"redis\" |
                    .services.redis.image=\"redis:8.2.1\" |
                    .services.redis.expose=[6379] |
                    .services.redis.volumes=[\"./volumes/redis:/data\"] |
                    .services.redis.healthcheck={
                    \"test\" : [\"CMD-SHELL\",\"redis-cli ping | grep PONG\"],
                    \"timeout\" : \"5s\",
                    \"interval\" : \"1s\",
                    \"retries\" : 5
                    } |
                    .services.authelia.depends_on.redis.condition=\"service_healthy\""
    fi

    host="$host" registered_domain="$registered_domain" authelia_url="$domain"/authenticate redirect_url="$domain" \
        update_yaml_file "$authelia_config_file_yaml" "./volumes/authelia/configuration.yml"

    authelia_schema="authelia" update_yaml_file "$authelia_docker_service_yaml" "$compose_file"
fi

echo -e "$env_vars" >>.env

if [[ "$proxy" == "caddy" ]]; then
    mkdir -p "$caddy_local_volume"

    # https://stackoverflow.com/a/3953712/18954618
    echo "
    import $caddySnippetsPath/cors.conf

    {\$DOMAIN} {
        $([[ "$CI" == true ]] && echo "tls internal")
        @supa_api path /rest/v1/* /auth/v1/* /realtime/v1/* /functions/v1/*

        $([[ "$with_authelia" == true ]] && echo "@authelia path /authenticate /authenticate/*
        handle @authelia {
                reverse_proxy authelia:9091
        }
        ")

        handle @supa_api {
		    reverse_proxy kong:8000
	    }

        handle_path /storage/v1/* {
            import cors *
            reverse_proxy storage:5000
        }

        handle /upload/resumable* {
            import cors *
            reverse_proxy storage:5000
        }

        handle_path /goapi/* {
            reverse_proxy kong:8000
        }

       	handle {
            $([[ "$with_authelia" == false ]] && echo "basic_auth {
			    {\$PROXY_AUTH_USERNAME} {\$PROXY_AUTH_PASSWORD}
		    }" || echo "forward_auth authelia:9091 {
                        uri /api/authz/forward-auth

                        copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
                }")	    	

		    reverse_proxy studio:3000
	    }
      	
        header -server
}" >"$caddyfile_local"
else
    mkdir -p "$(dirname "$nginx_local_template_file")"

    # mounted local ./volumes/nginx/snippets to this path inside container
    nginxSnippetsPath="/etc/nginx/user_conf.d/snippets"

    # cert path inside container https://github.com/JonasAlfredsson/docker-nginx-certbot/blob/master/docs/good_to_know.md#how-the-script-add-domain-names-to-certificate-requests
    certPath="/etc/letsencrypt/live/supabase-automated-self-host"

    echo "    
upstream kong_upstream {
        server kong:8000;
        keepalive 2;
}

server {
	    listen 443 ssl;
 	    listen [::]:443 ssl;
 	    http2 on;
        server_name \${NGINX_SERVER_NAME};
        server_tokens off;
        proxy_http_version 1.1;

        proxy_set_header Host \$host;
        proxy_set_header X-Original-URL \$scheme://\$http_host\$request_uri;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-URI \$request_uri;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Real-IP \$remote_addr;

        ssl_certificate         $certPath/fullchain.pem;
        ssl_certificate_key     $certPath/privkey.pem;
        ssl_trusted_certificate $certPath/chain.pem;
    
        ssl_dhparam /etc/letsencrypt/dhparams/dhparam.pem;

        location /realtime {
            proxy_pass http://kong_upstream;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \"upgrade\";
            proxy_read_timeout 3600s;
        }

        location /storage/v1/ {
            include $nginxSnippetsPath/cors.conf;
            client_max_body_size 0;
            proxy_pass http://storage:5000/;
        }

        location /upload/resumable {
            include $nginxSnippetsPath/cors.conf;
            client_max_body_size 0;
            proxy_pass http://storage:5000;
        }

    	location /goapi/ {
		    proxy_pass http://kong_upstream/;
	    }

        location /rest {
            proxy_pass http://kong_upstream;
        }

        location /auth {
            proxy_pass http://kong_upstream;
        }

        location /functions {
            proxy_pass http://kong_upstream;
        }

        $([[ $with_authelia == true ]] && echo "
        include $nginxSnippetsPath/authelia-location.conf;

    	location /authenticate {
	     	include $nginxSnippetsPath/proxy.conf;
		    proxy_pass http://authelia:9091;
	    }")

        location / {
            $(
        [[ $with_authelia == false ]] && echo "auth_basic \"Admin\";
            auth_basic_user_file $nginx_pass_file;
            " || echo "            
            include $nginxSnippetsPath/proxy.conf;
		    include $nginxSnippetsPath/authelia-authrequest.conf;
            "
    )
            proxy_pass http://studio:3000;
        }
}

server {
    listen 80;
	listen [::]:80;
    server_name \${NGINX_SERVER_NAME};
    return 301 https://\$server_name\$request_uri;
}
" >"$nginx_local_template_file"
fi

unset password confirmPassword
if [ -n "$SUDO_USER" ]; then chown -R "$SUDO_USER": .; fi

echo -e "\n🎉 Success!"
echo "👉 Next steps:"
echo "1. Change into the docker directory:"
echo "   cd $directory/docker"
echo "2. Start the services with Docker Compose:"
echo "   docker compose up -d"
echo "🚀 Everything should now be running!"

echo -e "\n🌐 To access the dashboard over the internet, ensure your firewall allows traffic on ports 80 and 443\n"
