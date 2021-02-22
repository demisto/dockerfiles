
FROM demisto/crypto:1.0.0.16776

COPY requirements.txt .
COPY ansible /home/demisto/ansible

RUN apk --update add --no-cache libressl-dev musl-dev libffi-dev openssl-dev build-base sudo python3 openssl \
     ca-certificates sshpass openssh-client rsync \
    && pip install --no-cache-dir -r requirements.txt
RUN ansible-galaxy install -c geerlingguy.homebrew
RUN ansible-galaxy install -c ctorgalson.oh-my-zsh,v2.2.2
RUN ansible-galaxy install -c pddg.anyenv
RUN ansible-galaxy install elliotweiser.osx-command-line-tools --force
