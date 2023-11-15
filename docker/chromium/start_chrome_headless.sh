#!/bin/bash

for value in {1..3}
do
    echo "Trying to start chrome, attempt $value"
    ps -aux | grep "chrome" | grep "9222" > /dev/null 2>&1
    if [[ "$?" == "0" ]]; then
        echo "Chrome is running"
        exit 0
    else
        echo "Chrome is not running"
        service dbus restart
        nohup /opt/google/chrome/google-chrome --headless --disable-gpu --no-sandbox --hide-scrollbars --disable_infobars --start-maximized --start-fullscreen --ignore-certificate-errors --disable-dev-shm-usage --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36" --remote-debugging-port=9222 & disown
    fi
    sleep 3
done
