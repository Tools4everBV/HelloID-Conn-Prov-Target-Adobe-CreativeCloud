# HelloID-Conn-Prov-Target-Adobe-CreativeCloud
<br />
<p align="center">
  <img src="https://www.tools4ever.nl/connector-logos/adobecreativecloud-logo.png">
</p> 
<br />

This connector allows you to create, update and delete Federated IDs in Adobe Creative Cloud.

## Table of Contents
* [Setup the Adobe Project](#setup-the-adobe-project)

## Setup the Adobe Project
1. Follow the steps in the Adobe guide linked below for setting up service account integration.

https://developer.adobe.com/developer-console/docs/guides/authentication/ServiceAccountIntegration/

2. With the public and private key generated during setup use openssl to create a PFX certificate file for use in generating the JWT token.

```
openssl pkcs12 -export -out AdobeCreativeCloud.pfx -inkey private.key -in certificate_pub.crt
```

_For more information about our HelloID PowerShell connectors, please refer to our general [Documentation](https://docs.helloid.com/hc/en-us/articles/360012557600-Configure-a-custom-PowerShell-source-system) page_

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
