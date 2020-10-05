FROM demisto/python3-deb:3.8.5.11787

COPY requirements.txt .

RUN apt-get update && apt-get install -y python3-dev g++

RUN pip install spacy
RUN pip install --trusted-host github.com https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-2.1.0/en_core_web_sm-2.1.0.tar.gz
RUN pip install --no-cache-dir -r requirements.txt




