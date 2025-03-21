# py3-native Changelog

## Unreleased

## 8.8.0

## 8.7.0

* Updated the library ***exchangelib*** to version ***5.4.2***  to allow support for the **EWSv2**  integration.
* Added the library ***ntlm_auth*** to allow support for the **EWSv2**  integration.
* Updated the image to use Python 3.11.
* Added the ***json2html*** library to allow support for the ***Json2HtmlTable*** script.

## 8.6.0

* Added support for the **auth-utils** image.

## 8.4.0

* Added *jq* as a build dependency and updated chromedriver download script to be in line with chromium.
* Updated py3-native to be based on ubi-9.2.
* Downgraded the *LibreOffice* to the following version: **7.1.8** to avoid installing it directly from the source.
* Added support for the **netutils** image.

## 8.3.0

* Updated the *LibreOffice* to the following version: **7.5.3**
* Added the *iproute* library to allow support for the **DockerHardeningCheck** script.

## 8.2.0

* Updated py3-native to be based on ubi-9.1.
* Updated the *LibreOffice* to the following version: **7.5.1**
* Fixed an issue where sometimes when trying to retrieve *LibreOffice* installation from *download.documentfoundation.org* website, the chosen mirror was broken.
* LibreOffice will now be installed always from the same mirror.
