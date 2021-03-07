
FROM demisto/crypto:1.0.0.16776


# Installing sudo to emulate normal OS behavior...
RUN apk --update add sudo

# Adding python run time..
RUN apk --update add python3 openssl ca-certificates
RUN apk --update add --virtual build-dependencies python3-dev libffi-dev openssl-dev build-base
RUN pip3 install --upgrade pip cffi

# Installing ansible
RUN pip3 install ansible==2.9.1
RUN apk --no-cache --update add bash py-dnspython py-boto py-netaddr bind-tools html2text php7 php7-json git jq curl
RUN pip3 install --no-cache-dir --upgrade yq
RUN pip3 install --no-cache-dir --upgrade mitogen

# Installing handy tools (not absolutely required)...
RUN apk --update add sshpass openssh-client rsync

# Removing package list...
RUN apk del build-dependencies
RUN rm -rf /var/cache/apk/*

# Adding hosts for convenience...
RUN mkdir -p /etc/ansible
RUN echo 'localhost' > /etc/ansible/hosts
COPY ansible.cfg /etc/ansible/ansible.cfg

# Ansible roles
RUN ansible-galaxy install -c elliotweiser.osx-command-line-tools
RUN ansible-galaxy install -c geerlingguy.homebrew
RUN ansible-galaxy collection install -c community.general

# Volume your ansible configuration into the image
RUN mkdir -p /ansible/playbooks
WORKDIR /ansible/playbooks
VOLUME [ "/ansible/playbooks" ]

# # Run ansible to configure things
ENV ANSIBLE_HOST_KEY_CHECKING=False
ENTRYPOINT [ "ansible-playbook", "playbook.yml", "-v"]