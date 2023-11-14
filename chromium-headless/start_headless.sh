#!/bin/bash

# ./bootstrap.sh
# 
# mkdir -p /var/run/dbus/system_bus_socket
# python -c "import socket; s = socket.socket(socket.AF_UNIX); s.bind('/var/run/dbus/system_bus_socket')"
# dbus-daemon --session --nofork --nosyslog --nopidfile --address=unix:path=/var/run/dbus/system_bus_socket &
# nohup Xvfb -ac :99 -screen 0 1280x1024x16 &
# export DISPLAY=:99
# # service --status-all
# service cups restart
# mkdir -p /usr/share/cups/model/Generic/
# # && cp /usr/share/ppd/cups-pdf/CUPS-PDF_noopt.ppd /usr/share/cups/model/
# cp /usr/share/ppd/cups-pdf/CUPS-PDF_noopt.ppd /usr/share/cups/model/Generic/
# lpadmin -p cups-pdf -v cups-pdf:/ -E -P /usr/share/ppd/cups-pdf/CUPS-PDF_opt.ppd


# nohup /opt/google/chrome/google-chrome --remote-debugging-port=5556 --no-sandbox --allow-running-insecure-content --ignore-certificate-errors --disable-content-security-policy --disable-dev-shm-usage --disable-proxy-certificate-handler --ignore-urlfetcher-cert-requests --disable-test-root-certs --kiosk-printing --print-to-pdf --no-first-run --disable-print-preview --start-maximized --enable-automation --disable-browser-side-navigation --disable-gpu &

/start_chrome_headless.sh > /dev/null 2> /dev/null

# nohup /opt/google/chrome/google-chrome --headless=new --no-sandbox --disable-gpu --hide-scrollbars --disable_infobars --start-maximized --start-fullscreen --ignore-certificate-errors --disable-dev-shm-usage --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36" --remote-debugging-port=5556 &
# nohup /opt/google/chrome/google-chrome --headless     --disable-gpu --no-sandbox --hide-scrollbars --disable_infobars --start-maximized --start-fullscreen --ignore-certificate-errors --disable-dev-shm-usage --user-agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.64 Safari/537.36" --remote-debugging-port=9222 & disown

python3
