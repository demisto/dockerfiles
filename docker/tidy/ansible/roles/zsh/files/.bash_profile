################################## Homebrew packages path ################################################
export PATH=/usr/local/bin:$PATH

################################## Pyenv configuration ####################################################
export PATH=$HOME/.pyenv/shims:$PATH
# eval "$(pyenv init -)"
# eval "$(pyenv virtualenv-init -)"

################################## Pipenv configuration ####################################################
export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
export PIPENV_PYTHON=$HOME/.pyenv/shims/python

################################## Demisto-sdk configuration ##############################################
export DEMISTO_README_VALIDATION="True"

################################## Demisto configuration ##################################################
# source ~/.demisto_bashrc

################################## Node JS firewall configuration #########################################
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/all_ca.pem

################################## Content git hooks ######################################################
export CONTENT_PRECOMMIT_RUN_DEV_TASKS=1

################################## Visual studio code ######################################################
code () { 
    VSCODE_CWD="$PWD"
    open -n -b "com.microsoft.VSCode" --args $* 
}

################################## Ansible develooper setup ################################################
alias dev-install="docker run -it -v ~/dev/etc/developer_setup/ansible_demisto:/ansible/playbooks devdemisto/developer_setup_ansible:1.0.5666"