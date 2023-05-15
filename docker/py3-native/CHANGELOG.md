# py3-native Changelog

## Unreleased
* Locked the installation of the *clang* package to version 14 due to dependency conflicts with the *tigervnc-server-minimal* package.
* Locked the installation of the *rust* package to version 1.62 due to dependency conflicts with the *tigervnc-server-minimal* package.
* Updated the *LibreOffice* to the following version: **7.5.3**
* Added the *iproute* library to allow support for the **DockerHardeningCheck** script.

## 8.2.0
* Updated py3-native to be based on ubi-9.1.
* Updated the *LibreOffice* to the following version: **7.5.1**
* Fixed an issue where sometimes when trying to retrieve *LibreOffice* installation from *download.documentfoundation.org* website, the chosen mirror was broken.
* LibreOffice will now be installed always from the same mirror. 