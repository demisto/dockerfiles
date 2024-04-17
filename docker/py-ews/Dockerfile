FROM demisto/python3-deb:3.10.14.91136

COPY requirements.txt .

RUN cp /etc/ssl/openssl.cnf /etc/ssl/openssl.cnf.org \
&& sed -i '/default = default_sect/a legacy = legacy_sect' /etc/ssl/openssl.cnf \
&& echo -e 'activate = 1\n\n[legacy_sect]\nactivate = 1\n' > /tmp/ssl.cnf \
&& echo -e 'ssl_conf = ssl_sect\n [ssl_sect]\n system_default = system_default_sect\n \n [system_default_sect]\n Options |= SSL_OP_IGNORE_UNEXPECTED_EOF\n' > /tmp/ssl.cnf \
&& sed -i '/\[default_sect\]/r /tmp/ssl.cnf' /etc/ssl/openssl.cnf \
&& sed -i '/# activate = 1/d' /etc/ssl/openssl.cnf \
&& rm /tmp/ssl.cnf 
