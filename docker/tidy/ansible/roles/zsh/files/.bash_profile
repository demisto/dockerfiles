export LC_ALL=en_US.UTF-8
export LANG=en_US.UTF-8
################################## Homebrew packages path ################################################
export PATH=/usr/local/bin:$PATH

################################## GO configuration ####################################################
export GOENV_ROOT="$HOME/.goenv"
export PATH="$GOENV_ROOT/bin:$PATH"
eval "$(goenv init -)"
export PATH="$GOROOT/bin:$PATH"
export PATH="$PATH:$GOPATH/bin"

################################## Pyenv configuration ####################################################
export PATH=$HOME/.pyenv/shims:$PATH
eval "$(pyenv init -)"

################################## Demisto configuration ##################################################
# source ~/.demisto_bashrc

################################## Node JS firewall configuration #########################################
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/all_ca.pem

################################## Demisto-sdk configuration ##############################################
export DEMISTO_README_VALIDATION="True"

################################## Content git hooks ######################################################
export CONTENT_PRECOMMIT_RUN_DEV_TASKS=1

################################## Visual studio code ######################################################
code () {
    VSCODE_CWD="$PWD"
    open -n -b "com.microsoft.VSCode" --args $*
}
