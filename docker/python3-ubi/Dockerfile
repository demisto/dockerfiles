ARG BASE_UBI_TAG=9.4
ARG BASE_UBI_VERSION=ubi9

FROM registry.access.redhat.com/${BASE_UBI_VERSION}:${BASE_UBI_TAG} as build

RUN dnf upgrade -y --nodocs && \
    dnf install -y --nodocs \
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
    dnf clean all && \
    rm -rf /var/cache/dnf

# when changing it make sure to change also PYTHON_VERSION env var in line 105
ARG PYTHON_VERSION_TO_INSTALL=3.11.9

# install python3.11.9
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION_TO_INSTALL}/Python-${PYTHON_VERSION_TO_INSTALL}.tgz && \
    mkdir -p /usr/local/src/python && \
    tar -zxf Python-${PYTHON_VERSION_TO_INSTALL}.tgz -C /usr/local/src/python --strip-components=1 && \
    rm -rf Python-${PYTHON_VERSION_TO_INSTALL}.tgz && \
    cd /usr/local/src/python && \
    ./configure \
      --enable-loadable-sqlite-extensions \
      --enable-optimizations \
      --enable-option-checking=fatal \
      --with-system-expat \
      --with-ensurepip \
      --with-lto \
      --with-computed-gotos \
      --enable-shared LDFLAGS="-Wl,-rpath /usr/local/lib" \
      --with-system-ffi \
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

RUN pip3.11 install -r requirements.txt

FROM registry.access.redhat.com/${BASE_UBI_VERSION}:${BASE_UBI_TAG}

RUN dnf update -y --nodocs && \
    dnf install -y --nodocs procps-ng && \
    dnf clean all && \
    rm -rf /var/cache/dnf

ENV PATH /usr/local/bin:/home/python/.local/bin:$PATH

# Relevant for tldextract
COPY --chmod=644 public_list.dat /var/public_list.dat

COPY --from=build /usr/local/include/python3.11 /usr/local/include/python3.11
COPY --from=build /usr/local/lib /usr/local/lib
COPY --from=build /usr/local/bin /usr/local/bin

RUN cd /usr/local/bin && \
    ln -s idle3.11 idle3 && \
    ln -s idle3 idle && \
    ln -s pydoc3.11 pydoc3 && \
    ln -s pydoc3 pydoc && \
    ln -s python3.11 python3 && \
    ln -s python3 python && \
    ln -s python3.11-config python3-config && \
    ln -s python3-config python-config && \
    ln -s easy_install-3.11 easy_install-3 && \
    ln -s easy_install-3 easy_install && \
    ln -s 2to3-3.11 2to3-3 && \
    ln -s 2to3-3 2to3 && \
    ln -s pip3.11 pip3 || true && \
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

RUN groupadd -g 4000 demisto && \
    useradd -u 4000 -g demisto demisto -s /bin/sh && \
    dnf remove python3-setuptools -y && \
    pip install --upgrade setuptools && \
    rpm -e --nodeps python3-setuptools-wheel


# when changing it make sure to change also PYTHON_VERSION_TO_INSTALL env var in line 23
ENV PYTHON_VERSION="3.11.9"
ENV LANG="C.UTF-8"

CMD ["python3"]

HEALTHCHECK NONE
