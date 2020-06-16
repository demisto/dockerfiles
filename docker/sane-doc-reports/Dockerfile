
FROM demisto/python3-deb:3.8.3.8715
WORKDIR "/app"

SHELL ["/bin/bash", "-c"]

RUN update-ca-certificates
RUN apt update -yq && apt upgrade -y && apt autoremove -yq \
    && apt install -y nodejs npm

RUN npm install svgexport@0.4.0 -g --unsafe-perm=true
RUN mkdir sandbox
COPY src sandbox/
WORKDIR sandbox
COPY requirements.txt .
RUN pip install -r requirements.txt && pip install -e .
