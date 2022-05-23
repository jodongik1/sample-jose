package jose.sample;

import java.io.File;
import java.io.FileReader;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date; 

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleFIPSProviderSingleton;

/**
 * 
 * JOSE 프로세스
 * 
 * 1. 수신측 공개키 송신측에 전달, 송신측 공개키 수신측에 전달
 * 2. 수신측 공개키로 대칭키(비밀키) 암호화 대칭키로 JWE 생성
 * 3. 송신측 개인키로 JWE 서명 후 JWS 생성 후 수신측에 JWE, JWS 전달
 * 4. 수신측에서는 JWS를 송신측 공개키로 서명 검증  
 * 5. 수신측에서는 JWE를 공객키로 대칭키 복호화 후 대칭키로 Payload 복호화. 
 *
 */
public class JOSESample {
	
    private final Logger logger = LoggerFactory.getLogger(this.getClass().getSimpleName());
	 
	private RSAPublicKey  sanderPublicKey;
	private RSAPrivateKey sanderPrivateKey; 
	
	private RSAPublicKey  receivePublicKey;
	private RSAPrivateKey receivePrivateKey;
	
	private final String SANDER_PUBLICKEY_PATH   = "keystore/sander_publickey.crt";
	private final String SANDER_PRIVATEKEY_PATH  = "keystore/sander_privatekey_pkcs8.key";
	
	private final String RECEIVE_PUBLICKEY_PATH  = "keystore/receive_publickey.crt";
	private final String RECEIVE_PRIVATEKEY_PATH = "keystore/receive_privatekey_pkcs8.key";
	
	private final JWEAlgorithm JWE_ALGORITHM         = JWEAlgorithm.RSA_OAEP_512; 
	private final EncryptionMethod ENCRYPTION_METHOD = EncryptionMethod.A256GCM;
	private final JWSAlgorithm JWS_ALGORITHM         = JWSAlgorithm.PS256;

	/**
	 * RSA Keypair 생성
	 * 
	 * @throws Exception
	 */
	private void initRsaKeyPair() throws Exception{
		String prefix = this.getClass().getResource("/").getPath(); 
		logger.debug("RSA PREFIX_PATH : ",prefix);
		
		// 송신측
		sanderPublicKey  = readPublicKey(new File(prefix + SANDER_PUBLICKEY_PATH)); // 공개키
		sanderPrivateKey = readPrivateKey(new File(prefix + SANDER_PRIVATEKEY_PATH)); // 개인키
		
		// 수신측
		receivePublicKey = readPublicKey(new File(prefix + RECEIVE_PUBLICKEY_PATH)); // 공개키
		receivePrivateKey= readPrivateKey(new File(prefix + RECEIVE_PRIVATEKEY_PATH)); // 개인키
		
	}
	
	/**
	 * JWE
	 * 
	 * @return
	 * @throws Exception
	 */
	private String jwe() throws Exception{ 
		// Generate the Content Encryption Key (CEK)
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(ENCRYPTION_METHOD.cekBitLength());
		SecretKey cek = keyGenerator.generateKey();
		
		// *alg () : [RSA-OAEP-256] - algorithm used to encrypt the randomly generated symmetric Content Encryption Key (CEK)
		// *kid () : Issuer's API Key 64 characters - 송신측 API Key.
		// *typ () : JOSE - JOSE(Javascript Object Signing and Encryption)
		// *enc () : [ENCRYPTION_METHOD] - CEK to encrypt sensitive payload elements.
		// *iat () : JWE timestamp in UTC fromat yyyy-MM-ddTHH:mm:ss SSSz
		// *exp () : timestamp in UTC fromat yyyy-MM-ddTHH:mm:ss SSSz
		JWEHeader jwe_header = new JWEHeader.Builder(JWE_ALGORITHM, ENCRYPTION_METHOD)
											.type(JOSEObjectType.JOSE)
											.contentType("JWE")
											.keyID("API_KEY_64")
											.customParam("iat", new Date().getTime())
											.customParam("exp", new Date().getTime())
											.build(); 
		
		// Encrypt the JWE with the RSA public key + specified AES CEK
		Payload jwe_paylod = new Payload("Hello World!!");
		JWEObject jwe = new JWEObject(jwe_header, jwe_paylod);
		jwe.encrypt(new RSAEncrypter(receivePublicKey, cek));    
		String jweString = jwe.serialize();
		logger.debug("JWE : "+jweString);
		return jweString;
	}
	
	/**
	 * JWS 
	 * 
	 * @param jweString
	 * @return
	 * @throws Exception
	 */
	private String jws( String jweString ) throws Exception {
		
		
		// Create RSA signer and set BC FIPS provider
		JWSSigner signer = new RSASSASigner(sanderPrivateKey); // 송신측 개인키
		signer.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());
		
		Payload jws_paylod = new Payload(jweString);
		JWSHeader jws_header = new JWSHeader.Builder(JWS_ALGORITHM)
											.keyID("API_KEY_64")
											.type(JOSEObjectType.JOSE)
											.contentType("JWE")
											.build();
		
		JWSObject jws = new JWSObject( jws_header, jws_paylod );
		jws.sign(signer);
		
		String jwsString = jws.serialize();
		logger.debug("JWS : "+jwsString+"");
		
		return jwsString;
	} 
	
	/**
	 * 서명 검증 및 복호화
	 * 
	 * @param jweString JWE 구조 - Base64URL (UTF8(JWE Header))||'.'||Base64URL (JWE Encrypted Key)||'.'||Base64URL (JWE Initialization Vector)||'.'||Base64URL (JWE Ciphertext)||'.'||Base64URL (JWE Authentication Tag)
	 * @param jwsString JWS 구조 - Base64URL (UTF8(JWS Header))||'.'||Base64URL (JWE)||'.'||Base64URL (JWS Signature)
	 * @throws Exception
	 */
	public void verifyNdecrypt(String jweString, String jwsString ) throws Exception{
		// Create RSA verifier and set BC FIPS provider
		JWSVerifier verifier = new RSASSAVerifier(sanderPublicKey); // 송신측 공개키 
		verifier.getJCAContext().setProvider(BouncyCastleFIPSProviderSingleton.getInstance());
		
		JWSObject jws = JWSObject.parse(jwsString);
		logger.debug("JWS Header : "+jws.getHeader().toString()+"");
	 
		// Verify signature - 서명 검증 true 경우에만 복호화 처리 수행. false 서명 검증 실패(무결성 오류)
		logger.debug("JWS signature verify : "+jws.verify(verifier)+"");
		
		// Decrypt the JWE with the RSA private key
		JWEObject jwe = JWEObject.parse(jweString);
		logger.debug("JWE Header : "+jwe.getHeader().toString()+"");
		
		jwe.decrypt(new RSADecrypter(receivePrivateKey)); // 수신측 개인키로 비밀키 복호화 후 비밀키로 Payload 복호화 처리 
		logger.debug("JWE Payload : "+jwe.getPayload().toString()+"");
	} 
	
	/**
	 * 공개키
	 * 
	 * @param file
	 * @return
	 * @throws Exception
	 */
	private RSAPublicKey readPublicKey(File file) throws Exception {
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    try (FileReader keyReader = new FileReader(file);
	      PemReader pemReader = new PemReader(keyReader)) {
	        PemObject pemObject = pemReader.readPemObject();
	        byte[] content = pemObject.getContent();
	        X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
	        return (RSAPublicKey) factory.generatePublic(pubKeySpec);
	    }
	}
	
	/**
	 * 개인키
	 * 
	 * @param file
	 * @return
	 * @throws Exception
	 */
	private RSAPrivateKey readPrivateKey(File file) throws Exception{
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    try (FileReader keyReader = new FileReader(file);
	      PemReader pemReader = new PemReader(keyReader)){
	        PemObject pemObject = pemReader.readPemObject();
	        byte[] content = pemObject.getContent();
	        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
	        return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
	    }
	}
	
	/**
	 * Main 테스트
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception{
		JOSESample jose = new JOSESample();
		jose.initRsaKeyPair();
		String jwe = jose.jwe();
		String jws = jose.jws(jwe); 
		jose.verifyNdecrypt(jwe, jws);  
	}
}
