FROM demisto/python3-ubi:3.10.8.90164
ADD https://s3.amazonaws.com/redshift-downloads/drivers/odbc/2.1.0.0/AmazonRedshiftODBC-64-bit-2.1.0.0.x86_64.rpm redshift.rpm
COPY odbcinst.ini /etc/odbcinst.ini
COPY amazon.redshiftodbc.ini /etc/amazon.redshiftodbc.ini

RUN yum -y install unixODBC && yum -y --nogpgcheck localinstall redshift.rpm

ENV AMAZONREDSHIFTODBCINI=/etc/amazon.redshiftodbc.ini
ENV ODBCSYSINI=/etc
ENV ODBCINI=/etc/odbcinst.ini