# make sure regex is working cause in new versions there are problems
import regex
pattern = regex.Regex('\\\\d\\+', flags=regex.V0)
print('regex is good')

import ssl
if ssl.OPENSSL_VERSION_INFO >= (3,0,0,0,0):
    print ('openSSL version changed.\
           Please validate SSL Legacy renegotiation error is not an issue.\
           If SSL Legacy renegotiation error occurs, please refer to python3 image Dockerfile for reference.')    
    exit(1)
print('openSSL version is good.')
    
