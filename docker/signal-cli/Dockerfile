
FROM demisto/python3-deb:3.9.1.15758

COPY requirements.txt .

RUN mkdir -p /usr/share/man/man1 && apt-get update && apt-get install -y --no-install-recommends \
  openjdk-11-jre-headless \
  wget \
  && rm -rf /var/lib/apt/lists/*

ENV SIGNAL_CLI_VERSION=0.7.4

RUN wget https://github.com/AsamK/signal-cli/releases/download/v"${SIGNAL_CLI_VERSION}"/signal-cli-"${SIGNAL_CLI_VERSION}".tar.gz \
  && tar xf signal-cli-"${SIGNAL_CLI_VERSION}".tar.gz -C /opt \
  && ln -sf /opt/signal-cli-"${SIGNAL_CLI_VERSION}"/bin/signal-cli /usr/local/bin/ \
  && rm signal-cli-"${SIGNAL_CLI_VERSION}".tar.gz

RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python3-dev \
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python3-dev \
&& rm -rf /var/lib/apt/lists/*
