#!/usr/bin/env bash

# This script will add / edit openssl.cnf lines to be:

# openssl_conf = openssl_init
# [openssl_init]
# ssl_conf = ssl_sect
# [ssl_sect]
# system_default = system_default_sect
# [system_default_sect]
# Options = UnsafeLegacyRenegotiation

destination_file='/etc/ssl/openssl.cnf'

sed -iE "s/^openssl_conf = .*/openssl_conf = openssl_init/" $destination_file
if ! grep -q "openssl_conf = openssl_init" $destination_file; then
	echo "openssl_conf = openssl_init" >> "$destination_file"
fi
if ! grep -qF "[openssl_init]" $destination_file; then
	echo "[openssl_init]" >> "$destination_file"
	echo "ssl_conf = ssl_sect" >> "$destination_file"
fi
sed -iE "s/^ssl_conf = .*/ssl_conf = ssl_sect/" $destination_file
if ! grep -qF "[ssl_sect]" $destination_file; then
	echo "[ssl_sect]" >> "$destination_file"
	echo "system_default = system_default_sect" >> "$destination_file"
fi
sed -iE "s/system_default = .*/system_default = system_default_sect/" $destination_file
if ! grep -qF "[system_default_sect]" $destination_file; then
	echo "[system_default_sect]" >> "$destination_file"
	echo "Options = UnsafeLegacyRenegotiation" >> "$destination_file"
fi
sed -iE "s/Options = .*/Options = UnsafeLegacyRenegotiation/" $destination_file