################################## ZSH configuration #####################################################
export ZSH="$HOME/.oh-my-zsh"
ZSH_THEME="powerlevel10k/powerlevel10k"
plugins=(git pip docker virtualenv zsh-autosuggestions zsh-syntax-highlighting)
source $ZSH/oh-my-zsh.sh

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

################################## Demisto configuration ##################################################
# source ~/.demisto_bashrc

################################## Node JS firewall configuration #########################################
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/all_ca.pem

################################## Demisto-sdk configuration ##############################################
# eval "$(_DEMISTO_SDK_COMPLETE=source_zsh demisto-sdk)"
export DEMISTO_README_VALIDATION="True"

################################## Content git hooks ######################################################
export CONTENT_PRECOMMIT_RUN_DEV_TASKS=1

################################## Visual studio code ######################################################
code () { 
    VSCODE_CWD="$PWD"
    open -n -b "com.microsoft.VSCode" --args $* 
}

################################## GO ######################################################
export GOENV_ROOT=$HOME/.goenv
export GOPATH=$HOME/dev/go
export PATH=$GOENV_ROOT/bin:$GOPATH/bin:$PATH
export GOENV_DISABLE_GOPATH=1
eval "$(goenv init -)"

################################## Ansible develooper setup ################################################
alias dev-install="docker run -it -v ~/dev/etc/developer_setup/ansible_demisto:/ansible/playbooks devdemisto/developer_setup_ansible:1.0.5666"


