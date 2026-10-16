#!/bin/sh
# Local frontend liveness. Arguments override env-mode settings for file deployments:
# healthcheck.sh [http|https [listen-host [port]]]
set -eu

setting() {
    setting_name=$1
    setting_default=$2
    if setting_value=$(printenv "$setting_name"); then
        if printenv "${setting_name}_FILE" >/dev/null; then
            echo "Healthcheck: configure $setting_name or its _FILE input, not both" >&2
            exit 1
        fi
        printf '%s' "$setting_value"
    elif setting_file=$(printenv "${setting_name}_FILE"); then
        tr -d '\r' < "$setting_file"
    else
        printf '%s' "$setting_default"
    fi
}

if [ "$#" -gt 3 ]; then
    echo 'Usage: healthcheck.sh [http|https [listen-host [port]]]' >&2
    exit 1
fi
if [ "$#" -gt 0 ]; then
    scheme=$1
else
    case "$(setting NM__TLS__ENABLED true)" in
        true) scheme=https ;;
        false) scheme=http ;;
        *) echo 'Healthcheck: invalid NM__TLS__ENABLED' >&2; exit 1 ;;
    esac
fi
host=${2:-$(setting NM__SERVER__HOST 0.0.0.0)}
port=${3:-$(setting NM__SERVER__PORT 9999)}
case "$port" in
    ''|*[!0-9]*) echo 'Healthcheck: invalid port' >&2; exit 1 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || exit 1
case "$host" in
    0.0.0.0) host=127.0.0.1 ;;
    ::) host=::1 ;;
    '') echo 'Healthcheck: empty listen host' >&2; exit 1 ;;
esac
case "$host" in
    *:*) address="[$host]" ;;
    *) address=$host ;;
esac

# The probe connects locally even when the container has an outbound HTTP proxy.
set -- --fail --silent --show-error --connect-timeout 2 --max-time 4 --noproxy '*' --output /dev/null
case "$scheme" in
    http) exec curl "$@" "http://$address:$port/login" ;;
    https)
        name=${SERVER_TLS_NAME:-localhost}
        ca=${SERVER_TLS_CA_FILE:-/etc/network-mapping/tls/ca.pem}
        exec curl "$@" --cacert "$ca" --connect-to "$name:$port:$address:$port" \
            "https://$name:$port/login"
        ;;
    *) echo 'Healthcheck: protocol must be http or https' >&2; exit 1 ;;
esac
