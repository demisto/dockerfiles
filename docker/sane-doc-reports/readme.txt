May need to add:
` && echo $(echo -n | openssl s_client -showcerts -connect github.com:443 2>/dev/null  | \
        sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p') >> /etc/ssl/certs/ca-certificates.crt \`
To the docker file for github certs (after the firewall).