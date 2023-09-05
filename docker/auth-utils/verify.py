#!/usr/bin/env python3

from azure.kusto.data.response import KustoResponseDataSet, KustoResponseDataSetV1
import pem
from akamai.edgegrid import EdgeGridAuth
import jwt 
from pydantic import BaseConfig, BaseModel, AnyUrl
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import BackendApplicationClient
from requests_ntlm import HttpNtlmAuth

print("auth-utils docker image verified")