#!/bin/bash

# Default values (consider injecting them from the outside as arguments)
ignore_certificate_errors=true
chrome_binary="/opt/google/chrome/google-chrome"
remote_debugging_port=9222
max_attempts=3
user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"

while [[ "$#" -gt 0 ]]; do
    case "${1}" in
        --validate-certificates) ignore_certificate_errors=false ;;
        --chrome-binary) chrome_binary="${2}"; shift ;;
        --user-agent) user_agent="${2}"; shift ;;
        --port) remote_debugging_port="${2}"; shift ;;
        *) echo "Unknown option: ${1}" ;;
    esac
    shift
done

local cert_errors_option=""
if [ "$ignore_certificate_errors" = true ]; then
    cert_errors_option="--ignore-certificate-errors"
fi

echo "Starting Chrome..."
nohup "$chrome_binary" --headless --disable-gpu --no-sandbox --hide-scrollbars --disable-infobars --start-maximized --start-fullscreen $cert_errors_option --disable-dev-shm-usage --user-agent="\"$user_agent\"" --remote-debugging-port="$remote_debugging_port" & disown
