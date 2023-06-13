#
# NOTE: THIS DOCKERFILE IS BASED ON: https://raw.githubusercontent.com/docker-library/python/f1e613f48eb4fc88748b36787f5ed74c14914636/2.7/buster/slim/Dockerfile
# We only change to use the latest debian version. 

# Last modified: 2023-06-13T00:13:25.904570+00:00
FROM debian:bullseye-slim

# ensure local python is preferred over distribution python
ENV PATH /usr/local/bin:$PATH

# http://bugs.python.org/issue19846
# > At the moment, setting "LANG=C" on a Linux system *fundamentally breaks Python 3*, and that's not OK.
ENV LANG C.UTF-8
# https://github.com/docker-library/python/issues/147
ENV PYTHONIOENCODING UTF-8

# runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
		ca-certificates \
		netbase \
	&& rm -rf /var/lib/apt/lists/*

# taken from here: https://salsa.debian.org/cpython-team/python2/-/blob/master/debian/patches/CVE-2021-3177.diff
COPY CVE-2021-3177.diff .

ENV GPG_KEY C01E1CAD5EA2C4F0B8E3571504C367C218ADD4FF
ENV PYTHON_VERSION 2.7.18

RUN set -ex \
	\
	&& savedAptMark="$(apt-mark showmanual)" \
	&& apt-get update && apt-get install -y --no-install-recommends \
		dpkg-dev \
		gcc \
		libbz2-dev \
		libc6-dev \
		libdb-dev \
		libgdbm-dev \
		libncursesw5-dev \
		libreadline-dev \
		libsqlite3-dev \
		libssl-dev \
		make \
		tk-dev \
		wget \
		xz-utils \
		zlib1g-dev \
# as of Stretch, "gpg" is no longer included by default
		$(command -v gpg > /dev/null || echo 'gnupg dirmngr') \
	\
	&& wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz" \
	&& wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc" \
	&& export GNUPGHOME="$(mktemp -d)" \
	&& gpg --batch --keyserver keyserver.ubuntu.com --recv-keys "$GPG_KEY" \
	&& gpg --batch --verify python.tar.xz.asc python.tar.xz \
	&& { command -v gpgconf > /dev/null && gpgconf --kill all || :; } \
	&& rm -rf "$GNUPGHOME" python.tar.xz.asc \
	&& mkdir -p /usr/src/python \
	&& tar -xJC /usr/src/python --strip-components=1 -f python.tar.xz \
	&& rm python.tar.xz \
	&& patch -d /usr/src/python -p1 < CVE-2021-3177.diff \
	\
	&& cd /usr/src/python \
	&& gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)" \
	&& ./configure \
		--build="$gnuArch" \
		--enable-optimizations \
		--enable-option-checking=fatal \
		--enable-shared \
		--enable-unicode=ucs4 \
	&& make -j "$(nproc)" \
# setting PROFILE_TASK makes "--enable-optimizations" reasonable: https://bugs.python.org/issue36044 / https://github.com/docker-library/python/issues/160#issuecomment-509426916
		PROFILE_TASK='-m test.regrtest --pgo \
			test_array \
			test_base64 \
			test_binascii \
			test_binhex \
			test_binop \
			test_bytes \
			test_c_locale_coercion \
			test_class \
			test_cmath \
			test_codecs \
			test_compile \
			test_complex \
			test_csv \
			test_decimal \
			test_dict \
			test_float \
			test_fstring \
			test_hashlib \
			test_io \
			test_iter \
			test_json \
			test_long \
			test_math \
			test_memoryview \
			test_pickle \
			test_re \
			test_set \
			test_slice \
			test_struct \
			test_threading \
			test_time \
			test_traceback \
			test_unicode \
		' \
	&& make install \
	&& ldconfig \
	\
	&& apt-mark auto '.*' > /dev/null \
	&& apt-mark manual $savedAptMark \
	&& find /usr/local -type f -executable -not \( -name '*tkinter*' \) -exec ldd '{}' ';' \
		| awk '/=>/ { print $(NF-1) }' \
		| sort -u \
		| xargs -r dpkg-query --search \
		| cut -d: -f1 \
		| sort -u \
		| xargs -r apt-mark manual \
	&& apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
	&& rm -rf /var/lib/apt/lists/* \
	\
	&& find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \
			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \
		\) -exec rm -rf '{}' + \
	&& rm -rf /usr/src/python \
	\
	&& python2 --version

# if this is called "PIP_VERSION", pip explodes with "ValueError: invalid truth value '<VERSION>'"
ENV PYTHON_PIP_VERSION 20.3.4
# https://github.com/pypa/get-pip
ENV PYTHON_GET_PIP_URL https://github.com/pypa/get-pip/raw/831b5dd0bec03caf24aa6d736a28dc2ba80f91cc/public/2.7/get-pip.py
ENV PYTHON_GET_PIP_SHA256 40ee07eac6674b8d60fce2bbabc148cf0e2f1408c167683f110fd608b8d6f416

RUN set -ex; \
	\
	savedAptMark="$(apt-mark showmanual)"; \
	apt-get update; \
	apt-get install -y --no-install-recommends wget; \
	\
	wget -O get-pip.py "$PYTHON_GET_PIP_URL"; \
	echo "$PYTHON_GET_PIP_SHA256 *get-pip.py" | sha256sum --check --strict -; \
	\
	apt-mark auto '.*' > /dev/null; \
	[ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; \
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*; \
	\
	python get-pip.py \
		--disable-pip-version-check \
		--no-cache-dir \
		"pip==$PYTHON_PIP_VERSION" \
	; \
	pip --version; \
	\
	find /usr/local -depth \
		\( \
			\( -type d -a \( -name test -o -name tests -o -name idle_test \) \) \
			-o \
			\( -type f -a \( -name '*.pyc' -o -name '*.pyo' \) \) \
		\) -exec rm -rf '{}' +; \
	rm -f get-pip.py

CMD ["python2"]

# END Docker file fromhttps://raw.githubusercontent.com/docker-library/python/f1e613f48eb4fc88748b36787f5ed74c14914636/2.7/buster/slim/Dockerfile

RUN echo 'deb http://deb.debian.org/debian bullseye-backports main' >> /etc/apt/sources.list

# Basic linux utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
  procps \
&& rm -rf /var/lib/apt/lists/*

# Upgrade all packages to latest
RUN apt-get update && apt-get -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

# Upgrade using backports
RUN apt-get update && apt-get -t bullseye-backports -y --no-install-recommends upgrade \
&& rm -rf /var/lib/apt/lists/*

RUN rm CVE-2021-3177.diff
COPY requirements.txt .

#Install tools for building binary deps (will be reomved later on)
RUN apt-get update && apt-get install -y --no-install-recommends \
  gcc \
  python2-dev \ 
&& pip install --no-cache-dir -r requirements.txt \
&& apt-get purge -y --auto-remove \
  gcc \
  python2-dev \
&& rm -rf /var/lib/apt/lists/*

RUN groupadd --gid 4000 demisto \
  && useradd --uid 4000 --gid demisto --shell /bin/bash --create-home demisto
