
FROM demisto/python3-deb:3.10.7.35175


RUN apt-get update && apt-get install -y --no-install-recommends curl \
  && curl -fsSL https://get.rvm.io | bash -s stable  \
  && gem install aquatone