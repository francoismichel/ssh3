#! /bin/bash

# we strongly recommend using classical certificates through e.g. letencrypt
# however, if you want a comparable security level to OpenSSH's host keys,
# you can use this script to generate a self-signed certificate for every host
# and every IP address to install on your server
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout priv.key -days 3660 -out cert.pem -subj "/C=XX/O=Default Company/OU=XX/CN=selfsigned.h3sh" -addext "subjectAltName = DNS:selfsigned.h3sh,DNS:*"