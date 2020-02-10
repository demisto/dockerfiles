FROM oraclelinux:7-slim

ARG release=19
ARG update=5

RUN  yum -y install oracle-release-el7 && yum -y install oracle-epel-release-el7 && yum-config-manager --enable ol7_oracle_instantclient && yum -y install python36 && yum -y install python36-pip  && \
     yum -y install oracle-instantclient${release}.${update}-basic oracle-instantclient${release}.${update}-devel oracle-instantclient${release}.${update}-sqlplus oracle-instantclient${release}.${update}-tools &&  python3 -m pip install cx_Oracle && \
     rm -rf /var/cache/yum

ENV PATH=$PATH:/usr/lib/oracle/${release}.${update}/client64/bin
