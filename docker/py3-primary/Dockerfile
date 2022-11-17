
# TODO - update the image here
FROM devdemisto/py3-tools-ubi:1.0.0.37496

COPY requirements.txt .


COPY download_chromedriver.sh .

# chromium
RUN mkdir chromium && dnf install -y wget \
    && wget -O chromium/linux_signing_key.pub https://dl.google.com/linux/linux_signing_key.pub \
    && wget -O chromium/RPM-GPG-KEY-CentOS-Official https://www.centos.org/keys/RPM-GPG-KEY-CentOS-Official \
    && rpm --import chromium/linux_signing_key.pub \
    && rpm --import chromium/RPM-GPG-KEY-CentOS-Official \
    && dnf upgrade -y --nodocs \
    && dnf install -y --nodocs python3-devel gcc gcc-c++ make wget git unzip llvm-libs \
    && wget -O chromium/google-chrome-stable-101.0.4951.54-1.x86_64.rpm http://dl.google.com/linux/chrome/rpm/stable/x86_64/google-chrome-stable-101.0.4951.54-1.x86_64.rpm \
    && wget -O chromium/desktop-file-utils-0.23-8.el8.x86_64.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/desktop-file-utils-0.23-8.el8.x86_64.rpm \
    && wget -O chromium/liberation-fonts-2.00.3-7.el8.noarch.rpm http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-fonts-2.00.3-7.el8.noarch.rpm  \
    && wget -O chromium/liberation-sans-fonts-2.00.3-7.el8.noarch.rpm http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-sans-fonts-2.00.3-7.el8.noarch.rpm \
    && wget -O chromium/liberation-serif-fonts-2.00.3-7.el8.noarch.rpm http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/liberation-serif-fonts-2.00.3-7.el8.noarch.rpm \
    && wget -O chromium/mesa-vulkan-drivers-22.1.1-1.el8.x86_64.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/mesa-vulkan-drivers-22.1.1-1.el8.x86_64.rpm  \
    && wget -O chromium/vulkan-loader-1.2.189.0-1.el8.x86_64.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/vulkan-loader-1.2.189.0-1.el8.x86_64.rpm  \
    && wget -O chromium/xdg-utils-1.1.2-5.el8.noarch.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/xdg-utils-1.1.2-5.el8.noarch.rpm  \
    && wget -O chromium/dejavu-sans-mono-fonts-2.35-7.el8.noarch.rpm http://mirror.centos.org/centos/8-stream/BaseOS/x86_64/os/Packages/dejavu-sans-mono-fonts-2.35-7.el8.noarch.rpm \
    && dnf -y install chromium/ggoogle-chrome-stable-101.0.4951.54-1.x86_64.rpm chromium/desktop-file-utils-0.23-8.el8.x86_64.rpm \
    chromium/liberation-fonts-2.00.3-7.el8.noarch.rpm chromium/liberation-sans-fonts-2.00.3-7.el8.noarch.rpm chromium/liberation-serif-fonts-2.00.3-7.el8.noarch.rpm \
    chromium/mesa-vulkan-drivers-22.1.1-1.el8.x86_64.rpm .chromium/vulkan-loader-1.2.189.0-1.el8.x86_64.rpm chromium/xdg-utils-1.1.2-5.el8.noarch.rpm \
    chromium/dejavu-sans-mono-fonts-2.35-7.el8.noarch.rpm \
    && pip install --no-cache-dir --no-index -r requirements.txt \
    && ./download_chromedriver.sh \
    && unzip chromedriver_linux64.zip \
    && mv chromedriver /usr/bin/chromedriver \
    && rm -rf chromedriver_linux64.zip \
    && rm -rf chromium \
    && google-chrome --version \
    && chromedriver --version && \
    && dnf remove -y python3-devel gcc gcc-c++ make platform-python-pip unzip \
    && dnf clean all \
    && rm -rf /var/cache/dnf \


# tesseract - when installing a language package it is not added to tesseract when using --list-langs, need to check
RUN dnf update --nodocs  \
    && dnf upgrade --nodocs  \
    && mkdir tesseract \
    && wget -O tesseract/tesseract-4.1.1-2.el8.x86_64.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/tesseract-4.1.1-2.el8.x86_64.rpm \
    && wget -O tesseract/leptonica-1.76.0-2.el8.x86_64.rpm http://mirror.centos.org/centos/8-stream/AppStream/x86_64/os/Packages/leptonica-1.76.0-2.el8.x86_64.rpm \
    && dnf install -y tesseract/tesseract-4.1.1-2.el8.x86_64.rpm tesseract/leptonica-1.76.0-2.el8.x86_64.rpm \
    && git clone https://github.com/zdenop/tessdata_downloader.git \
    && mkdir /usr/local/share/tessdata \
    && for lang in eng ara chi_sim chi_sim_vert chi_tra chi_tra_vert deu fra heb ita jpn jpn_vert pol por rus spa swe tur ; \
    do python tessdata_downloader/tessdata_downloader.py -o /usr/local/share/tessdata/ -l $lang; done \
    && tesseract --version --list-langs \
    && rm -rf tessdata_downloader \
    && dnf remove -y git \
    && dnf clean all \
    && rm -rf /var/cache/dnf




# populate zeep's cache so offline can work too
#ENV ZEEP_STATIC_CACHE_DB=/zeep/static/cache.db
#COPY zeep-add-to-cache.py .
#
#
#COPY ./model_docker.pkl .
#
## handles dxl + crypto + oauthlib + py3ews + readpdf + iputils + bs4-py3 + pcap-http-extractor + unzip + parse-emails + docxpy + netutils + ssdeep + sklearn + pandas + zeep + python_pancloud_v2 + ippysocks + akamai + google-k8s-engine
## 1) sklearn image config
## 2) nltk image configuration
## 3) install all os libraries needed for the images above
## 4) zeep image config
## 5) mlurlphishing config
#ENV NLTK_DATA='/ml/nltk_data'
#RUN pip install --no-cache-dir -r requirements.txt \
#    && mkdir /ml \
#    && python -c "import nltk; nltk.download('wordnet', download_dir='/ml/nltk_data'); nltk.download('stopwords', download_dir='/ml/nltk_data'); nltk.download('punkt', download_dir='/ml/nltk_data')" \
#    && chown -R demisto:demisto /ml && chmod -R 775 /ml \
#    && mkdir /usr/local/share/nltk_data \
#    && chmod 755 /usr/local/share/nltk_data \
#    && python -m nltk.downloader -d /usr/local/share/nltk_data punkt \
#    && mkdir -p /usr/share/man/man1 \
#    && apt-get update && apt-get upgrade -y && apt-get install -y --no-install-recommends python3-dev build-essential cargo \
#    libxml2-dev poppler-utils iputils-ping p7zip-full unrar-free libmagic-dev bind9 ssdeep g++ openssh-server less htop make rsync openssl  \
#    libpng-dev libffi-dev libxslt-dev libfreetype-dev liblapack-dev gfortran musl-dev libopenblas-dev libopenblas-base libgomp1 libgpgme11 libreoffice default-jre-headless \
#    libglib2.0-0 libsm6 libxext6 libgl1-mesa-glx libxrender1 libxrender-dev \
#    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
#    && ln -s /usr/include/locale.h /usr/include/xlocale.h \
#    && mkdir -p /zeep/static \
#    && chmod 755 /zeep \
#    && chmod 755 /zeep/static \
#    && python zeep-add-to-cache.py https://www.w3.org/2005/05/xmlmime \
#    && python zeep-add-to-cache.py http://www.w3.org/2005/05/xmlmime \
#    && mkdir /model \
#    && mv model_docker.pkl /model/model_docker.pkl \
#    && chmod -R 775 /model \
#    && apt-get purge -y --auto-remove python3-dev build-essential zlib1g-dev curl libxrender-dev \
#    && apt-get clean \
#    && rm -rf /var/lib/apt/lists/* \
#    && rm -rf /root/.cargo \
#    && pip uninstall -y pcodedmp
