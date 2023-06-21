ARG BASE_UBI_TAG=ubi-minimal:9.2
ARG BASE_UBI_VERSION=ubi9

FROM registry.access.redhat.com/${BASE_UBI_VERSION}/${BASE_UBI_TAG} as build

RUN microdnf upgrade -y --nodocs && \
    microdnf install -y --nodocs \
       tar \
       findutils \
       bzip2-devel \
       expat-devel \
       gcc \
       libffi-devel \
       libuuid-devel \
       make \
       openssl-devel \
       sqlite-devel \
       wget \
       zlib-devel \
       xz-devel && \
    microdnf clean all && \
    rm -rf /var/cache/microdnf

# install python3
RUN wget https://www.python.org/ftp/python/3.10.8/Python-3.10.8.tgz && \
    mkdir -p /usr/local/src/python && \
    tar -zxf Python-3.10.8.tgz -C /usr/local/src/python --strip-components=1 && \
    rm -rf Python-3.10.8.tgz && \
    cd /usr/local/src/python && \
    ./configure \
      --enable-loadable-sqlite-extensions \
      --enable-optimizations \
      --enable-option-checking=fatal \
      --with-system-expat \
      --with-ensurepip \
      --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib" \
      --prefix=/usr/local && \
    make && \
    make altinstall

RUN find /usr/local -depth \
	\( \
		\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
		-o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name '*.a' \) \) \
	\) -exec rm -rf '{}' + && \
    echo '/usr/local/lib' > /etc/ld.so.conf && \
    ldconfig

COPY requirements.txt .
RUN pip3.10 install -r requirements.txt

FROM registry.access.redhat.com/${BASE_UBI_VERSION}/${BASE_UBI_TAG}

RUN microdnf update -y --nodocs && \
    microdnf install -y --nodocs procps-ng && \
    microdnf clean all && \
    rm -rf /var/cache/microdnf

ENV PATH /usr/local/bin:/home/python/.local/bin:$PATH

COPY --from=build /usr/local/include/python3.10 /usr/local/include/python3.10
COPY --from=build /usr/local/lib /usr/local/lib
COPY --from=build /usr/local/bin /usr/local/bin

RUN cd /usr/local/bin && \
    ln -s idle3.10 idle3 && \
    ln -s idle3 idle && \
    ln -s pydoc3.10 pydoc3 && \
    ln -s pydoc3 pydoc && \
    ln -s python3.10 python3 && \
    ln -s python3 python && \
    ln -s python3.10-config python3-config && \
    ln -s python3-config python-config && \
    ln -s easy_install-3.10 easy_install-3 && \
    ln -s easy_install-3 easy_install && \
    ln -s 2to3-3.10 2to3-3 && \
    ln -s 2to3-3 2to3 && \
    ln -s pip3.10 pip3 || true && \
    ln -s pip3 pip || true && \
    echo '/usr/local/lib' > /etc/ld.so.conf && \
    ldconfig


# Handling the issue described here https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000POJ0CAO&lang=en_US%E2%80%A9
# by enabling UnsafeLegacyRenegotiation
RUN cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.org \
    && echo -e 'ssl_conf = ssl_sect\n\
[ssl_sect]\n\
system_default = system_default_sect\n\
\n\
[system_default_sect]\n\
Options = UnsafeLegacyRenegotiation\n' > /tmp/ssl.cnf \
    && sed -i '/providers = provider_sect/r /tmp/ssl.cnf' /etc/pki/tls/openssl.cnf \
    && rm /tmp/ssl.cnf \
    && grep -C 10 'Options = UnsafeLegacyRenegotiation' /etc/pki/tls/openssl.cnf

RUN microdnf update -y --nodocs && \
    microdnf install -y --nodocs shadow-utils && \
    groupadd -g 4000 demisto && \
    useradd -u 4000 -g demisto demisto -s /bin/sh

CMD ["python3"]

HEALTHCHECK NONE
