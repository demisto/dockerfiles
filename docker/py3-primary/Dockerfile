FROM demisto/mlurlphishing:1.0.0.28347 as mlurlphishing

FROM devdemisto/py3-tools-ubi:1.0.0.37605

COPY requirements.txt .

# chromium
COPY chromium/download_chromedriver.sh .
COPY repos/google-chrome.repo /etc/yum.repos.d/

# will always install the latest stable google-chrome version
RUN dnf update --nodocs -y  \
    && dnf upgrade -y --nodocs \
    && dnf install -y wget \
    && wget https://dl.google.com/linux/linux_signing_key.pub \
    && wget https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official \
    && rpm --import linux_signing_key.pub \
    && rpm --import RPM-GPG-KEY-CentOS-Official \
    && dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git unzip llvm-libs google-chrome-stable \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/desktop-file-utils-0.23-8.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-fonts-2.00.3-7.el8.noarch.rpm  \
    http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-sans-fonts-2.00.3-7.el8.noarch.rpm \
    http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-serif-fonts-2.00.3-7.el8.noarch.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/mesa-vulkan-drivers-22.1.1-1.el8.x86_64.rpm  \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/vulkan-loader-1.2.189.0-1.el8.x86_64.rpm  \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/xdg-utils-1.1.2-5.el8.noarch.rpm  \
    http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/dejavu-sans-mono-fonts-2.35-7.el8.noarch.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/tigervnc-1.12.0-7.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/fltk-1.3.4-5.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/mesa-libGLU-9.0.0-15.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/tigervnc-icons-1.12.0-7.el8.noarch.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/tigervnc-license-1.12.0-7.el8.noarch.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/xorg-x11-utils-7.5-28.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/libXv-1.0.11-7.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/libXxf86dga-1.1.5-1.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/libdmx-1.1.4-3.el8.x86_64.rpm \
    && ./download_chromedriver.sh \
    && unzip chromedriver_linux64.zip \
    && mv chromedriver /usr/bin/chromedriver \
    && rm -rf chromedriver_linux64.zip \
    && google-chrome --version \
    && chromedriver --version \
    && dnf remove -y python3-devel gcc gcc-c++ make platform-python-pip unzip \
    && dnf clean all \
    && rm -rf /var/cache/dnf \
    && rm -rf download_chromedriver.sh


# tesseract
RUN dnf install -y git \
    && dnf install -y http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/tesseract-4.1.1-2.el8.x86_64.rpm \
    http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/leptonica-1.76.0-2.el8.x86_64.rpm \
    && git clone https://github.com/zdenop/tessdata_downloader.git \
    && for lang in eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
    do python tessdata_downloader/tessdata_downloader.py -o /usr/share/tesseract/tessdata/ -l $lang; done \
    && tesseract --version --list-langs \
    && rm -rf tessdata_downloader \
    && dnf remove -y git \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# copy the model from mlurlphishing image
COPY --from=mlurlphishing /model /model

# this is being done because when trying to unzip the rpm inside the container doesn't work, hence copying it as rpm.
COPY office-utils/LibreOffice_7.4.2.3_Linux_x86-64_rpm LibreOffice_Linux_x86-64_rpm

# handles os dependancies for: crypto + readpdf + parse-emails + docxpy + sklearn + pandas + ippysocks-py3 + oauthlib
# unzip + py3ews + taxii2 + pan-os-python + slackv3 + google-api-py3 + boto3py3
# pyjwt3 + joe-security + slack + mlurlphishing + office-utils
# note: the packages that are being removed by dnf remove at the end are packages that are required during the installation of python dependancies

# crypto os dependancies: python3-devel gcc gcc-c++ make wget git rust cargo libffi-devel openssl-devel
# readpdf os dependancies: poppler poppler-utils
# parse-emails os dependancies: libffi-devel, python3-devel, wget, git
# docxpy os dependancies: libxml2-devel, libxslt-devel, python3-devel, wget
# sklearn os dependancies: python3-devel gcc gcc-c++ make wget git openssh curl ca-certificates openssl less make rsync libpng-devel freetype-devel gcc-gfortran.x86_64 openblas unzip
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
# mlurlphishing os dependancies: python3-devel gcc libjpeg-turbo-devel glib2-devel libSM libXext mesa-libGL libXrender-devel
# office-utils os dependancies: LibreOffice_Linux_x86-64_rpm java-11-openjdk-headless cairo libSM libX11-xcb

# lines 6-8 are the RPMs for unrar and p7zip (unzip image)
# lines 9-10 are the RPMs for libjpeg-turbo-devel and libXrender-devel (mlurlphishing image)
# line 11 - since in ubi its 7za --> need to make it to run as 7z like our script
# lines 11-13 is the configuration for sklearn
# line 14 - install the demisto_ml image
# lines 15 - add punkt for sklearn image
# lines 21-23 - installing libreoffice for the office-utils image
RUN dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git poppler poppler-utils \
        rust cargo libxml2-devel libxslt-devel \
        libffi-devel openssl-devel curl libffi glib2-devel libSM libXext mesa-libGL libXrender \
        openssh ca-certificates openssl less rsync libpng-devel freetype-devel gcc-gfortran.x86_64 openblas unzip libstdc++ \
        http://mirror.dogado.de/fedora-epel/8/Everything/x86_64/Packages/p/p7zip-16.02-20.el8.x86_64.rpm \
        https://mirror.dogado.de/fedora-epel/8/Everything/x86_64/Packages/u/unrar-0.1.1-1.el8.x86_64.rpm \
        https://mirror.dogado.de/fedora-epel/8/Everything/x86_64/Packages/u/unrar-free-0.1.1-1.el8.x86_64.rpm \
        http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/libjpeg-turbo-devel-1.5.3-12.el8.x86_64.rpm \
        http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/libXrender-devel-0.9.10-7.el8.x86_64.rpm \
        && ln -s /usr/bin/7za /usr/bin/7z \
        && pip install --no-cache-dir -r requirements.txt \
        && mkdir /ml \
        && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
        && chown -R demisto:demisto /ml && chmod -R 775 /ml \
        && chmod -R 775 /model \
        && dnf install -y --nodocs java-11-openjdk-headless cairo libX11-xcb \
        && dnf localinstall -y LibreOffice_Linux_x86-64_rpm/RPMS/*.rpm \
        && rm -rf LibreOffice_Linux_x86-64_rpm \
        && dnf remove -y python3-devel rust cargo libffi-devel openssl-devel gcc gcc-c++ make git platform-python-pip libXrender-devel \
        gcc-gfortran pkgconf-pkg-config \
        && rm -rf demisto_ml-0.2.tar.gz \
        && dnf clean all \
        && rm -rf /var/cache/dnf \
        && rm -rf /root/.cargo \
        && pip uninstall -y pcodedmp

# add libreoffice to path
ENV PATH=$PATH:/opt/libreoffice7.4/program
ENV NLTK_DATA='/ml/nltk_data'
