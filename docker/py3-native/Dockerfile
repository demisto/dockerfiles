FROM demisto/py3-tools-ubi:1.0.0.45881

COPY requirements.txt .
COPY chromium/download_chromedriver.sh .
COPY repos /repos

ARG LEPTONICA_VERSION=1.82.0
ARG TESSERACT_VERSION=5.2.0

# handles chromium + tesseract
# for tesseract - followed instructions from here: https://computingforgeeks.com/install-tesseract-ocr-on-rocky-almalinux/
RUN dnf update --nodocs -y  \
    && dnf upgrade -y --nodocs \
    && dnf install --nodocs -y wget git \
    && wget https://dl.google.com/linux/linux_signing_key.pub \
    && wget https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official \
    && rpm --import linux_signing_key.pub \
    && rpm --import RPM-GPG-KEY-CentOS-Official \
    && mv repos/* /etc/yum.repos.d/ \
    && dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git unzip llvm-libs libXpm \
    && dnf install -y --nodocs --enablerepo=rocky8-base --enablerepo=rocky8-release tigervnc-server-minimal xorg-x11-utils google-chrome-stable \
    && dnf install -y --nodocs --enablerepo=rocky8-base --enablerepo=rocky8-release --enablerepo=fedora-epel ImageMagick \
    && ./download_chromedriver.sh \
    && unzip chromedriver_linux64.zip \
    && mv chromedriver /usr/bin/chromedriver \
    && rm -rf chromedriver_linux64.zip \
    && google-chrome --version \
    && chromedriver --version \
    && dnf install -y --nodocs git automake make autoconf libtool clang zlib zlib-devel libjpeg libjpeg-devel libwebp libwebp-devel libtiff libtiff-devel libpng libpng-devel pango giflib \
    && dnf install -y https://vault.centos.org/centos/8/PowerTools/x86_64/os/Packages/giflib-devel-5.1.4-3.el8.x86_64.rpm \
    && git clone --depth 1 -b $LEPTONICA_VERSION https://github.com/DanBloomberg/leptonica \
    && cd leptonica \
    && ./autogen.sh && ./configure && make && make install && ldconfig \
    && cd .. \
    && git clone --depth 1 -b $TESSERACT_VERSION https://github.com/tesseract-ocr/tesseract.git \
    && cd tesseract \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./autogen.sh  \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig ./configure  \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig gmake \
    && PKG_CONFIG_PATH=/usr/local/lib/pkgconfig make install \
    && ldconfig \
    && cd .. \
    && git clone https://github.com/zdenop/tessdata_downloader.git \
    && for lang in eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
    do python tessdata_downloader/tessdata_downloader.py -o /usr/local/share/tessdata/ -l $lang; done \
    && tesseract --version --list-langs \
    && rm -rf tessdata_downloader leptonica tesseract download_chromedriver.sh repos \
    && dnf remove -y python3-devel gcc gcc-c++ make platform-python-pip unzip git make autoconf automake libtool libpng-devel libjpeg-devel libtiff-devel zlib-devel giflib-devel \
    && dnf clean all \
    && rm -rf /var/cache/dnf


ARG LIBRE_OFFICE_FULL_VERSION=7.4.4
ARG LIBRE_OFFICE_INSTALLATION_FILE_NAME=LibreOffice_${LIBRE_OFFICE_FULL_VERSION}_Linux_x86-64_rpm
# libre-office mirrors are taken from here - http://download.documentfoundation.org/libreoffice/stable/

# handles os dependancies for: crypto + readpdf + parse-emails + docxpy + sklearn + pandas + ippysocks-py3 + oauthlib
# unzip + py3ews + taxii2 + pan-os-python + slackv3 + google-api-py3 + boto3py3
# pyjwt3 + joe-security + slack + office-utils

# line 6 - since in ubi its 7za --> need to make it to run as 7z like our script
# lines 8-10 is the configuration for sklearn
# linex 11-14 - install LibreOffice for the office-utils image
RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git poppler poppler-utils \
        rust cargo libxml2-devel libxslt-devel \
        libffi-devel openssl-devel curl libffi libSM mesa-libGL \
        openssh ca-certificates openssl less rsync libpng-devel freetype-devel gcc-gfortran openblas unzip libstdc++ \
        && dnf install -y --nodocs --enablerepo=fedora-epel p7zip unrar \
        && ln -s /usr/bin/7za /usr/bin/7z \
        && pip install --no-cache-dir -r requirements.txt \
        && mkdir /ml \
        && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
        && chown -R demisto:demisto /ml && chmod -R 775 /ml \
        && dnf install -y --nodocs java-11-openjdk-headless cairo libX11-xcb \
        && wget https://mirror.isoc.org.il/pub/tdf/libreoffice/stable/${LIBRE_OFFICE_FULL_VERSION}/rpm/x86_64/${LIBRE_OFFICE_INSTALLATION_FILE_NAME}.tar.gz \
        && tar -xzvf ${LIBRE_OFFICE_INSTALLATION_FILE_NAME}.tar.gz --one-top-level=${LIBRE_OFFICE_INSTALLATION_FILE_NAME} --strip-components 1 \
        && dnf localinstall -y ${LIBRE_OFFICE_INSTALLATION_FILE_NAME}/RPMS/*.rpm \
        && rm -rf ${LIBRE_OFFICE_INSTALLATION_FILE_NAME}.tar.gz ${LIBRE_OFFICE_INSTALLATION_FILE_NAME} \
        && dnf remove -y python3-devel rust cargo libffi-devel openssl-devel gcc gcc-c++ make git platform-python-pip \
        && dnf clean all \
        && rm -rf /var/cache/dnf \
        && rm -rf /root/.cargo \
        && pip uninstall -y pcodedmp


ARG LIBRE_OFFICE_MAJOR_VERSION=7.4

# add libreoffice to path
ENV PATH=$PATH:/opt/libreoffice$LIBRE_OFFICE_MAJOR_VERSION/program
ENV NLTK_DATA='/ml/nltk_data'
