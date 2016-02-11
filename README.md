lemur-digicert
==============

DigiCert Plugin for [Lemur](https://github.com/Netflix/lemur)

This plugin provides Issuer support for the DigiCert v2.0 API.
The plugin supports both standard and private SSL certificate types, and
will choose between "SSL Plus" and "SSL Multi-Domain" depending on whether
SANs are present or not.

Setup
-----
To install the plugin, add the following lines to your lemur.conf.py file:
```python
# DigiCert Plugin (CertCentral, API v2)
DIGICERT_URL = 'https://www.digicert.com/services/v2'
DIGICERT_ACCOUNT_ID = (your account ID)
DIGICERT_API_KEY = (your API key)
DIGICERT_REQUEST_TYPE = ['SSL_PLUS' | 'PRIVATE_SSL_PLUS'] (choose one)
DIGICERT_ORG_ID = (your DigiCert org ID)
DIGICERT_CA_CERT_ID = (only required for PRIVATE_SSL_PLUS)
DIGICERT_SIGNATURE_HASH = 'sha256'
```

Deploy and install the files. For example using Docker, you can add the
following lines to your Dockerfile:
```python
# Install DigiCert Plugin
ADD lemur_digicert /usr/local/src/lemur/lemur_digicert
RUN cd /usr/local/src/lemur/lemur_digicert &&\
  pip install -e .
```

Go to the Authorities section of Lemur and add a new entry for DigiCert, choosing
DigiCert from the Plugin dropdown.

Usage
-----
You can request certs as usual using Lemur, just select the DigiCert certificate authority during creation! 
