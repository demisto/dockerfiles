# Last modified: 2026-07-26T12:49:56.990721+00:00

FROM demisto/powershell-ubuntu:7.5.0.11326619

RUN pwsh -c "Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop"
# Pin ExchangeOnlineManagement to 3.9.2. Version 3.10.0 introduced a regression in the
# compiled RestApiClient (build 15.21.0092) where an HTTP 401 claims-challenge response
# is surfaced as System.Net.Http.HttpResponseMessage, but the module still calls the
# legacy HttpWebResponse method GetResponseHeader('WWW-Authenticate') -> RuntimeException
# "does not contain a method named 'GetResponseHeader'". See XSUP-73321 / XSUP-73181.
# 3.9.2 (RestApiClient build 15.20.9456) handles the 401 claims path correctly.
RUN pwsh -c "Install-Module -Name ExchangeOnlineManagement -RequiredVersion 3.9.2 -Scope AllUsers -Force -ErrorAction Stop"
RUN pwsh -c "Install-Module -Name SelfSignedCertificate -Scope AllUsers -Force -ErrorAction Stop"
