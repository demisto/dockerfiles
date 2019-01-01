FROM circleci/node:9.11

RUN sudo apt-get install -y python-dev libxml2-dev libxslt1-dev zlib1g-dev python-setuptools jq
RUN sudo easy_install pip
RUN sudo npm install npm -g
RUN sudo pip install pykwalify
RUN sudo pip install awscli
RUN sudo pip install requests
RUN sudo pip install slackclient
RUN sudo pip install git+https://github.com/demisto/demisto-py.git@test-content
RUN sudo npm install -g jsdoc-to-markdown
RUN sudo pip install git+https://github.com/rahulrrixe/parinx.git@master
