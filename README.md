# HPE
CA chain validation

There are two files run.py and run2.py

run.py checks if the serial numbers of the certificates in the chain file exists in the CRL specified, hence we need two inputs for run.py i.e the chain file and a CRL file/URL. But since this is not how certificate path validation alogirithms are typically implemented i.e they check if the serial number of certificate exists in the CRL provided by certificate issuer at the CRL distribution point. so this is implemented in run2.py. hence we have only one input i.e the chain file, it obtains the CRL file from the CRL distribution points of the certificate issuer. 
hence we need internet connection to test the code if we are obtaining the CRL using the CRL URL.
since i couldn't find a revoked certificate online, i created my own CA self signed certificate and using this, i have created server certificate with a serial number 0x1e3a9301cfc7206383f9a531d, this certificate is named as test.pem in the /crt folder. this serial number exists in the root.crl present in the crl folder.

\crt folder <br>
chain.pem - is a chain of certificates from google.com <br>
test.pem - is a certificate i have created with a custom serial number <br>
chain+test.pem - is a chain of certificate with test.pem certificate in it.

\crl folder <br>
root.crl - is google.com root certificate crl file

packages required <br>
pem :- ```pip install pem``` <br>
openssl :- ```pip install pyopenssl``` <br>
cryprography, codecs, os, argparse, requests <br>
to install all requirements use ```pip install -r requirements.txt```

```
$ python run.py -h
usage: run.py [-h] (-crlf CRL_FILE | -crlu CRL_URL) -chf CHAIN_FILE

certificate chain validation

optional arguments:
  -h, --help       show this help message and exit
  -crlf CRL_FILE   specify the .crl file
  -crlu CRL_URL    specify the CRL URL
  -chf CHAIN_FILE  specify the certificate chain file
```

there are two inputs to run.py:- <br>
1) chain file (.pem format) in the crt folder , option to use is "-chf" <br>
2) CRL file (.crl format) in the crl folder, option to use is "-crlf" <br>
 or <br>
   CRL url, option to use is "-crlu" <br>

test commands:- <br>
python run.py -chf chain+test.pem -crlu http://crl.pki.goog/gsr2/gsr2.crl <br>
python run.py -chf chain+test.pem -crlf root.crl <br>
python run.py -chf chain.pem -crlu http://crl.pki.goog/gsr2/gsr2.crl <br>
python run.py -chf chain.pem -crlf root.crl <br>


```
$ python run2.py -h
usage: run2.py [-h] -chf CHAIN_FILE

certificate chain validation

optional arguments:
  -h, --help       show this help message and exit
  -chf CHAIN_FILE  specify the certificate chain file
```

there is only one input to run2.py:- <br>
1) chain file (.pem format) in the crt folder , option to use is "-chf" <br>

test commands:- <br>
python run2.py -chf chain+test.pem <br>
python run2.py -chf chain+test.pem \<br>
python run2.py -chf chain.pem <br>
python run2.py -chf chain.pem <br>
