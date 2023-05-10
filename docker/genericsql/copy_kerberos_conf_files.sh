#!/bin/sh

cp krb5.conf /etc/krb5.conf
cp $USER.keytab /etc/$USER.keytab

exec "$@"