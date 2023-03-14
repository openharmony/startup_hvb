make the private key:
    openssl genrsa -out test_priv.pem 2048

make the public key according to private key:
    openssl rsa -pubout -in test_priv.pem -out test_pub.pem