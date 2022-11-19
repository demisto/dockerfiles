FROM devdemisto/py3-tools-ubi:1.0.0.37496

COPY requirements.txt .

# chromium
COPY download_chromedriver.sh .
COPY chromium/google-chrome.repo /etc/yum.repos.d/

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

# copy model_docker.pkl for mlurlphishing
COPY ./model_docker.pkl /model/model_docker.pkl

# handles os dependancies for: crypto + readpdf + parse-emails + docxpy + sklearn + pandas + ippysocks-py3 +
# unzip + py3ews + taxii2 + pan-os-python + bs4-tld + slackv3 + google-api-py3 + boto3py3 +
# pyjwt3 + btfl-soup + joe-security + slack + pcap-http-extractor
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

# lines 5-7 are the RPMs for unrar and p7zip (unzip image)
# lines 8-9 are the RPMs for libjpeg-turbo-devel and libXrender-devel (mlurlphishing image)
# line 10 - since in ubi its 7za --> need to make it to run as 7z like our script
# lines 12-14 is the configuration for sklearn
# lines 15-17 is the configuration for mlurlphishing
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
        && pip install --no-cache-dir --no-index -r requirements.txt \
        && mkdir /ml \
        && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
        && chown -R demisto:demisto /ml && chmod -R 775 /ml \
        && mkdir /model \
        && mv model_docker.pkl model/model_docker.pkl \
        && chmod -R 775 /model \
        && dnf remove -y python3-devel rust cargo libffi-devel openssl-devel gcc gcc-c++ make git platform-python-pip libXrender-devel \
        && dnf clean all \
        && rm -rf /var/cache/dnf \
        && rm -rf /root/.cargo \
        && pip uninstall -y pcodedmp


ENV NLTK_DATA='/ml/nltk_data'
