FROM demisto/python3-ubi:3.10.8.90164
ADD https://s3.amazonaws.com/redshift-downloads/drivers/odbc/2.1.0.0/AmazonRedshiftODBC-64-bit-2.1.0.0.x86_64.rpm redshift.rpm
RUN yum --nogpgcheck localinstall redshift.rpm
