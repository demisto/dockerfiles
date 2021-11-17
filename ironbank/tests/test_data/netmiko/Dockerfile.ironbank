ARG BASE_REGISTRY=registry1.dso.mil
ARG BASE_IMAGE=ironbank/opensource/palo-alto-networks/demisto/python3
ARG BASE_TAG=3.9.6.22912
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}

COPY requirements.txt .

RUN mkdir ./pip-pkgs

COPY *.* ./pip-pkgs/

USER root

RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git && \
        pip install --no-cache-dir --no-index --find-links ./pip-pkgs/ -r requirements.txt &&  \
        dnf remove -y python3-devel gcc gcc-c++ make wget git && \
        dnf clean all && \
        rm -rf /var/cache/dnf
        rm -rf ./pip-pkgs

ENV DOCKER_IMAGE='${{BASE_REGISTRY}}/${{BASE_IMAGE}}:${{BASE_TAG}}'

HEALTHCHECK NONE