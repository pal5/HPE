import pem
import codecs
import requests
import argparse
import os
from OpenSSL import crypto
from cryptography.hazmat._oid import ObjectIdentifier

parser = argparse.ArgumentParser(description='certificate chain validation')
parser.add_argument('-chf', dest="CHAIN_FILE",required=True,default=None,help="specify the certificate chain file")
args=parser.parse_args()

"""
`oid` is an object identifier object
`valid` specifies if the certificate chain is valid or not, default is true and is set to None when certificate is revoke
"""
oid=ObjectIdentifier("2.5.29.31")
valid=True

certs=pem.parse_file(os.getcwd()+"\\crt\\"+args.CHAIN_FILE)

for i in range(0,len(certs)):
    """
    for i in range(0,len(certs)-1):
    if we reach the root certificate we can guarentee that the chain is valid, since the root is self signed and cannot exist in any issuer CRL file. hence we can parse only upto last but one certificate in the chain  i.e the certificate at the index len(certs)-2, hence we can specify the range as (0,len(certs)-1).
    i have gone upto len(certs) to only print all the certificates in the chain
    """

    cert = crypto.load_certificate(crypto.FILETYPE_PEM,str(certs[i]))
    dict_sn={}
    print("Certificate Details -",i+1)
    #print("X509 object = ",cert) # return X509 object
    #print("issuer = ",cert.get_issuer()) # return X509Name object
    #print("subject of certificate = ",cert.get_subject())
    #print("digest = ",cert.digest())
    #print("extension = ",cert.get_extension())
    #print("no. of extensions = ",cert.get_extension_count())
    #pubkey_object=cert.get_pubkey()
    #print("public key = ",crypto.dump_publickey(crypto.FILETYPE_PEM,pubkey_object))
    #print("public key = ",cert.get_pubkey().to_cryptography_key().public_numbers())
    #print("signature algo used = ",cert.get_signature_algorithm().decode('UTF-8'))
    #print("certificate version = ",cert.get_version())
    not_after=cert.get_notAfter().decode('UTF-8')   #decode byte return type to a string
    not_after=not_after[0:4]+"-"+not_after[4:6]+"-"+not_after[6:8]
    print("not after = ",not_after)   
    not_before=cert.get_notBefore().decode('UTF-8')
    not_before=not_before[0:4]+"-"+not_before[4:6]+"-"+not_before[6:8]
    print("not before = ",not_before)
    print("hex serial number = ",hex(cert.get_serial_number()))
    print("int serial number = ",cert.get_serial_number())
    print("certificate expired ? ",cert.has_expired())
    sn=cert.get_serial_number()

    crypto_X509_obj=cert.to_cryptography()
    """
    returns a cryptography.x509.Certificate object, we need to get the CRL distribution point of the certiificate issuer
    """

    #print("cryptography = ",crypto_X509_obj)
    #print("x509 cert = ",type(cert))
    #print("***********************")
    #print("crypto x509 cert = ",type(crypto_X509_obj))

    CRL_URL=crypto_X509_obj.extensions.get_extension_for_oid(oid).value[0].full_name[0].value
    print("CRL_URL = ",CRL_URL)
    resp = requests.get(CRL_URL)
    #print("Respones = ", resp)
    #print("Respones.Content = ",resp.content)
    crl_object = crypto.load_crl(crypto.FILETYPE_ASN1, resp.content)
    revoked_objects = crl_object.get_revoked()
    if revoked_objects:
        print("no. of serial numbers in CRL file = ",len(revoked_objects))
        for rvk in revoked_objects:
            print("hex serial = ",rvk.get_serial().decode('UTF-8'))
            print("int serial = ",int(rvk.get_serial().decode('UTF-8'),16))
            dict_sn[int(rvk.get_serial().decode('UTF-8'),16)]=True
    else:
        print("no revoked certificates in the current CRL")
    print()
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