* JOSE 프로세스
 
1. 수신측 공개키 송신측에 전달, 송신측 공개키 수신측에 전달
1. 수신측 공개키로 대칭키(비밀키) 암호화 대칭키로 JWE 생성
1. 송신측 개인키로 JWE 서명 후 JWS 생성 후 수신측에 JWE, JWS 전달
1. 수신측에서는 JWS를 송신측 공개키로 서명 검증  
1. 수신측에서는 JWE를 공객키로 대칭키 복호화 후 대칭키로 Payload 복호화. 

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
$ openssl genrsa -out sander_keypair.pem 2048
$ openssl genrsa -out receive_keypair.pem 2048

// To extract the public part, use the rsa context:
$ openssl rsa -in sander_keypair.pem -pubout -out sander_publickey.crt
$ openssl rsa -in receive_keypair.pem -pubout -out receive_publickey.crt

// convert the original keypair to PKCS#8 format with the pkcs8 context:
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in sander_keypair.pem -out sander_privatekey_pkcs8.key
$ openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in receive_keypair.pem -out receive_privatekey_pkcs8.key
		
```

* 알고리즘 설명
---
* 대칭키 암호화 기법(Symmetric-Key Cryptography)

단 하나의 키를 송신자와 수신자가 공유하는 방법으로 암호화 통신을 하는 방법이다. 
그러나 대칭키는 originality를 구분할 수 없다는 근본적인 문제점을 가지고 있다. 
만약 암호화 메세지가 노출되는 상황이 발생하면 송신자와 수신자 중 누구로부터 문제상황이 야기된 것인지 판별할 수가 없다. 
만약 대칭키 시스템을 이용하는 은행과 고객 사이에 보안상의 문제가 발생할 경우 잘잘못을 따질 수도 없고 손해를 입은 쪽이 
보상을 받을 수도 없는 상황이 발생하는 것이다.

* 비대칭 암호화 기법(Asymmetric-Key Cryptography)
* 공개키 암호화 기법(Public-Key Cryptography)
공개키 기법은 대칭키의 대안이라기보다는 대칭키를 보완해준다고 봐야 한다. 
공개키 시스템이 완벽한 대안으로써 사용되지 못하는 이유는 치명적인 단점이 있기 때문인데, 바로 속도가 느리다는 점이다. 
어마어마한 규모의 연산이 필요하기 때문에 대용량의 데이터를 암호화하기에는 적절한 방법이 아니다.
공개키 기법의 특징으로는 Public key와 Private key를 이용하여 양자간 암호화 통신이 이루어진다는 점이다.  
누군가의 공개키로 암호화 한 메세지는 개인키로 풀리고, 개인키로 암호화 한 메세지는 공개키로 풀린다.


그렇다면 왜 공개키 기법을 사용할까? 두 가지 이슈를 해결하기 위해서이다.
- key distribution : 암호화 통신을 위해서는 반드시 서로가 키를 알아야 하는데, 이 때 수신자에게 키를 안전하게 넘기기 위해(받는사람의 공개키로 암호화해서 보내면 된다.)
- digital signatures : 이 메세지가 정말로 송신자라고 주장하는 사람으로부터 왔는지 검증하기 위해
(대칭키로는 당연히 서명이 불가능하다. 서명을 하는 것은 본인의 개인키로만 가능하고, 확인은 모든 사람이 공개키로 할 수 있음)

* OAEP Diagram(Optimal Asymmetric Encryption padding)
RSA는 동일한 키 값을 사용하므로 중간에 암호문을 도청하더라도 해독이 어렵지만 동일한 문자가 사용되었음은 알아챌 수 있다. 
따라서 padding값과 추가 연산하여 같은 문자라도 다른 결과값이 나오도록 하고 있는데, 이를 OAEP라고 한다. 
OAEP는 CCA로부터 보다 안전해지며, r값이 매번 변하므로 같은 입력에 대하여 다른 출력을 얻을 수 있다. 
또한 부분 복원이 불가능하다.


