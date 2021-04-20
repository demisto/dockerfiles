
FROM demisto/crypto:1.0.0.16776

COPY requirements.txt .
COPY ansible /home/demisto/ansible
COPY ansible.cfg /etc/ansible/ansible.cfg

RUN apk --update add --no-cache --virtual .build-dependencies \
     libressl-dev musl-dev libffi-dev openssl-dev build-base \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del .build-dependencies
RUN apk --update add --no-cache openssl ca-certificates sshpass openssh-client rsync

RUN ansible-galaxy install -c elliotweiser.osx-command-line-tools
RUN ansible-galaxy install -c geerlingguy.homebrew
RUN ansible-galaxy install -c ctorgalson.oh-my-zsh,v2.2.2
RUN ansible-galaxy install -c pddg.anyenv
RUN ansible-galaxy collection install -c community.general
