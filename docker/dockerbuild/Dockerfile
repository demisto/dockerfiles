FROM cimg/python:3.10.5

SHELL [ "/bin/sh", "-c" ]

ADD requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt \
  && pyenv install 2.7.18 && pyenv versions | grep 2.7.18 \
  && pyenv install 3.7.6 && pyenv versions | grep 3.7.6 \
  && pyenv install 3.8.1 && pyenv versions | grep 3.8.1 \
  && pyenv install 3.9.0 && pyenv versions | grep 3.9.0 \
  && pyenv shell 3.7.6 && pyenv exec pip3 install --no-cache-dir -r requirements.txt
