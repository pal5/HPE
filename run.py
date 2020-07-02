import pem
import codecs
import requests
import argparse
import os
from OpenSSL import crypto

parser = argparse.ArgumentParser(description='certificate chain validation')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-crlf', dest="CRL_FILE",default="",help='specify the .crl file')
group.add_argument('-crlu', dest="CRL_URL",default=None,help='specify the CRL URL')
parser.add_argument('-chf', dest="CHAIN_FILE",required=True,default=None,help="specify the certificate chain file")
args=parser.parse_args()

"""
`dict_sn` is a boolean dictionary that contains a list of all serial numbers
`valid` specifies if the certificate chain is valid or not, default is true and is set to None when certificate is revoke
"""
dict_sn={}
valid=True

if args.CRL_URL:
    resp = requests.get(args.CRL_URL)
    crl_object = crypto.load_crl(crypto.FILETYPE_ASN1, resp.content)
else:
    crl_object=crypto.load_crl(crypto.FILETYPE_ASN1,open(os.getcwd()+'\\crl\\'+args.CRL_FILE,'rb').read())


#print(crl_object)

revoked_objects = crl_object.get_revoked()
"""
print("revoked object = tuple of Revocations")
print(revoked_objects)
"""
if revoked_objects:
    print("no. of serial numbers in CRL file = ",len(revoked_objects))
    for rvk in revoked_objects:
        dict_sn[int(rvk.get_serial().decode('UTF-8'),16)]=True
else:
    print("no revoked certificates in the current CRL")

#contents of dictionary `dict_sn`
print("serial numbers in certificate revocation list")
for key in dict_sn:
    print("int - ",key,"hex -",hex(key))

print()
certs=pem.parse_file(os.getcwd()+"\\crt\\"+args.CHAIN_FILE)
# return a pem object for each certificate 

"""
we start parsing from the beginning i.e the end-entity certificate and reach to the root certificate
"""
for i in range(0,len(certs)):
    cert = crypto.load_certificate(crypto.FILETYPE_PEM,str(certs[i]))
    #returns a X509 object
    
    print("Certificate Details -",i+1)
    #print("X509 object = ",cert) # return X509 object
    #print("no. of extensions = ",cert.get_extension_count())
    #print("public key = ",cert.get_pubkey().to_cryptography_key().public_numbers())
    #print("signature algo used = ",cert.get_signature_algorithm().decode('UTF-8'))
    #print("certificate version = ",cert.get_version())
    print("issuer = ",cert.get_issuer()) # return X509Name object
    print("subject of certificate = ",cert.get_subject())
    not_after=cert.get_notAfter().decode('UTF-8')      #decode bytes ( return type of get_notAfter() ) to a string
    not_after=not_after[0:4]+"-"+not_after[4:6]+"-"+not_after[6:8]
    print("not after = ",not_after)   
    not_before=cert.get_notBefore().decode('UTF-8')
    not_before=not_before[0:4]+"-"+not_before[4:6]+"-"+not_before[6:8]
    print("not before = ",not_before)
    pubkey_object=cert.get_pubkey()
    print("int serial number = ",cert.get_serial_number())
    print("hex serial number = ",hex(cert.get_serial_number()))
    print("certificate expired ? ",cert.has_expired())
    print()
    sn=cert.get_serial_number()
    if sn in dict_sn:
        print("Certificate ",i+1," in the chain has been revoked")
        print("Serial no = ",sn)
        print("Chain terminated ............................")
        valid=False
        break
if valid:
    print("Cetificate chain is valid")
else:
    print("Certificate chain is invalid")