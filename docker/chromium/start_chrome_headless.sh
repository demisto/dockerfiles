#!/bin/bash

# Default values (consider injecting them from the outside as arguments)
ignore_certificate_errors=true
chrome_binary="/opt/google/chrome/google-chrome"
remote_debugging_port=9222
max_attempts=3
user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36"


start_chrome() {
    local cert_errors_option=""
    if [ "$ignore_certificate_errors" = true ]; then
        cert_errors_option="--ignore-certificate-errors"
    fi

    echo "Starting Chrome..."
    if ! nohup "$chrome_binary" --headless --disable-gpu --no-sandbox --hide-scrollbars --disable-infobars --start-maximized --start-fullscreen $cert_errors_option --disable-dev-shm-usage --user-agent="\"$user_agent\"" --remote-debugging-port="$remote_debugging_port" &> /var/log/chrome/chrome_log.txt & disown; then
        echo "Failed to start Chrome."
        return 1
    fi
    return 0
}


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


# Retry loop to start up chrome
for attempt in $(seq 1 $max_attempts); do
    echo "Attempt $attempt of $max_attempts"

    # Check if Chrome is already running on the specified port
    if pgrep -f "$chrome_binary.*--headless.*--remote-debugging-port=$remote_debugging_port" > /var/log/chrome/pgrep_log.txt; then
        echo "Chrome is already running on port $remote_debugging_port."
        exit 0
    fi

    # Try to start Chrome
    if start_chrome; then
        echo "Chrome started successfully."
        exit 0
    fi

    sleep 3
done

echo "Failed to start Chrome after $max_attempts attempts."
exit 1