#!/usr/bin/env python3
import subprocess
from azure.kusto.data.response import KustoResponseDataSet, KustoResponseDataSetV1
import pem
from akamai.edgegrid import EdgeGridAuth
import jwt 
from pydantic import BaseConfig, BaseModel, AnyUrl
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.backends import default_backend
subprocess.check_output(['openssl', 'version'])

print("auth-utils docker image verified")