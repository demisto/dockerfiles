FROM demisto/mlurlphishing:1.0.0.28347 as mlurlphishing

FROM devdemisto/py3-tools-ubi:1.0.0.37715

COPY requirements.txt .
COPY chromium/download_chromedriver.sh .
COPY repos /repos

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
    && git clone --depth 1 https://github.com/DanBloomberg/leptonica.git \
    && cd leptonica \
    && ./autogen.sh && ./configure && make && make install && ldconfig \
    && cd .. \
    && git clone --depth 1 https://github.com/tesseract-ocr/tesseract.git \
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


# copy the model from mlurlphishing image
COPY --from=mlurlphishing /model /model

# handles os dependancies for: crypto + readpdf + parse-emails + docxpy + sklearn + pandas + ippysocks-py3 + oauthlib
# unzip + py3ews + taxii2 + pan-os-python + slackv3 + google-api-py3 + boto3py3
# pyjwt3 + joe-security + slack + mlurlphishing + office-utils
# note: the packages that are being removed by dnf remove at the end are packages that are required during the installation of python dependancies

# crypto os dependancies: python3-devel gcc gcc-c++ make wget git rust cargo libffi-devel openssl-devel
# readpdf os dependancies: poppler poppler-utils
# parse-emails os dependancies: libffi-devel, python3-devel, wget, git
# docxpy os dependancies: libxml2-devel, libxslt-devel, python3-devel, wget
# sklearn os dependancies: python3-devel gcc gcc-c++ make wget git openssh curl ca-certificates openssl less make rsync libpng-devel freetype-devel gcc-gfortran openblas unzip
# pandas os dependancies: python3-devel gcc gcc-c++ make wget git libstdc++
# ippysocks-py3 os dependancies: gcc python3-devel
# oauthlib os dependanices: python3-devel gcc gcc-c++ make wget git
# unzip os dependanices: python3-devel gcc gcc-c++ make wget git p7zip unrar unrar-free
# py3ews os dependanices: python3-devel gcc gcc-c++ make wget git libxml2-devel openssl-devel
# taxii2 os dependanices: python3-devel gcc gcc-c++ make wget git
# pan-os-python os dependanices: python3-devel gcc gcc-c++ make wget git
# slackv3 os dependanices: python3-devel gcc gcc-c++ make wget git libffi-devel
# google-api-py3 os dependanices: python3-devel gcc
# boto3py3 os dependanices: python3-devel gcc gcc-c++ make wget git
# pyjwt3 os dependanices: python3-devel gcc gcc-c++ make wget git
# joe-security os dependancies: python3-devel gcc gcc-c++ make wget git
# slack os dependancies: python3-devel gcc gcc-c++ make wget git libffi
# mlurlphishing os dependancies: python3-devel gcc libjpeg-turbo-devel glib2-devel libSM libXext mesa-libGL libXrender-devel libXrender
# office-utils os dependancies: LibreOffice_Linux_x86-64_rpm java-11-openjdk-headless cairo libSM libX11-xcb


# line 7 - since in ubi its 7za --> need to make it to run as 7z like our script
# lines 9-11 is the configuration for sklearn
# linex 14-16 - install LibreOffice for the office-utils image
# lines 21-23 - installing libreoffice for the office-utils image
RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git poppler poppler-utils \
        rust cargo libxml2-devel libxslt-devel \
        libffi-devel openssl-devel curl libffi glib2-devel libSM libXext mesa-libGL libXrender \
        openssh ca-certificates openssl less rsync libpng-devel freetype-devel gcc-gfortran openblas unzip libstdc++ \
        && dnf install -y --nodocs --enablerepo=fedora-epel p7zip unrar \
        && dnf install -y --nodocs --enablerepo=rocky8-base --enablerepo=rocky8-release libjpeg-turbo-devel libXrender-devel \
        && ln -s /usr/bin/7za /usr/bin/7z \
        && pip install --no-cache-dir -r requirements.txt \
        && mkdir /ml \
        && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
        && chown -R demisto:demisto /ml && chmod -R 775 /ml \
        && chmod -R 775 /model \
        && dnf install -y --nodocs java-11-openjdk-headless cairo libX11-xcb \
        && wget http://download.documentfoundation.org/libreoffice/stable/7.4.2/rpm/x86_64/LibreOffice_7.4.2_Linux_x86-64_rpm.tar.gz \
        && tar -xzvf LibreOffice_7.4.2_Linux_x86-64_rpm.tar.gz \
        && dnf localinstall -y LibreOffice_7.4.2.3_Linux_x86-64_rpm/RPMS/*.rpm \
        && rm -rf LibreOffice_7.4.2.3_Linux_x86-64_rpm LibreOffice_7.4.2_Linux_x86-64_rpm.tar.gz \
        && dnf remove -y python3-devel rust cargo libffi-devel openssl-devel gcc gcc-c++ make git platform-python-pip libXrender-devel \
        && dnf clean all \
        && rm -rf /var/cache/dnf \
        && rm -rf /root/.cargo \
        && pip uninstall -y pcodedmp

# add libreoffice to path
ENV PATH=$PATH:/opt/libreoffice7.4/program
ENV NLTK_DATA='/ml/nltk_data'
