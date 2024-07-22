FROM demisto/python3-9-deb:3.9.16.103780

#COPY requirements.txt .
COPY environment.yml .
ADD https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh minicondainstall.sh
RUN chmod +x minicondainstall.sh && ./minicondainstall.sh -b -u -p ~/miniconda3 && ~/miniconda3/bin/conda --version
ENV PATH=/root/miniconda3/bin/:$PATH
RUN apt-get update \
&& apt-get install -y --no-install-recommends pipenv build-essential \
  gcc \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev
#RUN pip install -r requirements.txt
#RUN pip install --no-binary :all: hdbscan==0.8.27
RUN conda init bash
SHELL ["/bin/bash", "-c"]
RUN conda env create -f environment.yml

RUN conda activate clusteringenv && \
    conda list --export > /tmp/conda_packages.txt && \
    mkdir -p /tmp/pkgs && \
    conda install --download-only -n temp_env -c conda-forge --copy -d /tmp/pkgs --file /tmp/conda_packages.txt

# Extract the downloaded packages
RUN cd /tmp/pkgs && \
    for pkg in *.tar.bz2; do tar -xvjf "$pkg"; done

RUN cd /tmp/pkgs && \
    for pkg in *.tar.bz2; do tar -xvjf "$pkg"; done

# Install the dependencies to the system interpreter using pip
RUN find /tmp/pkgs -name "*.whl" -exec python3 -m pip install {} \; && \
    find /tmp/pkgs -name "*.tar.gz" -exec python3 -m pip install {} \;

RUN apt-get purge -y --auto-remove gcc pipenv \
  python3-dev gfortran wget git g++ pkg-config libhdf5-dev && rm -rf minicondainstall.sh
