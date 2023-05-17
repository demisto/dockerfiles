#!/bin/sh

cp /etc/krb5.conf /etc/krb5.conf
cp /etc/$USER.keytab /etc/$USER.keytab

exec "$@"