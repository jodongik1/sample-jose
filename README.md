* git
```
$ git config --global user.name "jodongik1"
$ git config --global user.email jodongik.one@gmai.com
$ git remote add origin https://github.com/jodongik1/sample-jose.git
$ git branch -M main
$ git push -u origin main
```

* 사용 라이브러리
```
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.22</version>
</dependency>
<dependency>
     <groupId>org.bouncycastle</groupId>
     <artifactId>bc-fips</artifactId>
     <version>2.0.0</version>
     <optional>true</optional>
</dependency>
```	 

* 사용 알고리즘
- JWE Algorithm : RSA_OAEP_265
- JWE Encryption Method : A256GCM
- JWS Algorithm : PS256


```
// RSA Keypair 생성

// $ openssl genrsa -out visa_keypair.pem 2048
// $ openssl genrsa -out sc_keypair.pem 2048
		
// To extract the public part, use the rsa context:
$ openssl rsa -in visa_keypair.pem -pubout -out visa_publickey.crt
$ openssl rsa -in sc_keypair.pem -pubout -out sc_publickey.crt
		
// convert the original keypair to PKCS#8 format with the pkcs8 context:
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in visa_keypair.pem -out visa_privatekey_pkcs8.key
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in sc_keypair.pem -out sc_privatekey_pkcs8.key
```