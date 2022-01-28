# rsa-signature-example
RSA Signature Example

## Signature generation and validation

### By openssl 

All examples imply that you have already generated ssl-rsa key-pair with such command:
```bash
openssl genrsa -out private.pem 2048
```
and extracted public key:
```bash
openssl rsa -in private.pem -pubout > public.pub
```

### By Our SignatureUtils Java class
```java
    SignatureUtils.generateKeysPairToFiles("private.crt", "public.pub");
```

After it you can sign messages or any data by private key and sent data with signature to anybody who have public key and partner can verify that this message is signatures by you and is valid