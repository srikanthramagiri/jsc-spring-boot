package com.example.cryptography.controller;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.nio.charset.StandardCharsets;


@CrossOrigin(origins ="http://localhost:3000/")
@RestController
public class CryptographicController {

	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/GetCryptograhicTypes")
	public List<String> getCryptographicTypes() {
		List<String> cryptographicTypes = new ArrayList<String>();
		cryptographicTypes.add("1.Symmetric Key Cryptography");
		cryptographicTypes.add("2.Hashing");
		cryptographicTypes.add("3.Asymmetric Key Cryptography");
		cryptographicTypes.add("4.Base 64 Encoding");

		return cryptographicTypes;

	}

	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/SymmetricKeyCryptography")
	public String encryptUsingSymmetricKey(@RequestParam int option, @RequestParam String inputMsg) throws Exception {
		KeyGenerator keyGeneratorObj = KeyGenerator.getInstance("AES");
		keyGeneratorObj.init(256, new SecureRandom());
		SecretKey sKey = keyGeneratorObj.generateKey();
		IvParameterSpec spec = generateIvParameter();		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		byte[] encodedMsg = encodeMsg(cipher, sKey, spec, inputMsg);
		System.out.println("Encoded message : " + encodeToString(encodedMsg));

		String msg = new String(decodeMsg(cipher, sKey, spec, encodedMsg));
		System.out.println("Decoded message : " + msg);
		return encodeToString(encodedMsg);

	}

	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/Hashing")
	public String encryptUsingHashing(@RequestParam int option, @RequestParam String inputMsg) throws Exception {
		// we can do hashing with SHA3-256 or SHA-256 algorithm so now 
		//we are using SHA3-256 algorithm to do hashing
		MessageDigest md = MessageDigest.getInstance("SHA3-256");
		byte[] shabytes = md.digest(inputMsg.getBytes());
		StringBuilder strBuilder = new StringBuilder();
				for (byte b : shabytes) {
					strBuilder.append(String.format("%02x", b));
		        }
		System.out.println("hex:-"+strBuilder.toString());
		return strBuilder.toString();
	}

	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/AsymmetricKeyCryptography")
	public String encryptUsingAsymmetricKey(@RequestParam int option, @RequestParam String inputMsg) throws Exception {
		KeyPair keys = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		PrivateKey Pkey = keys.getPrivate();
		Signature signObj = Signature.getInstance("SHA256withRSA");
		byte[] message = inputMsg.getBytes();
		signObj.initSign(Pkey);
		signObj.update(message);
		byte[] signbytes = signObj.sign();
		System.out.println("sign:-"+ new String(signbytes, "UTF8"));
		
		PublicKey publickey = keys.getPublic();
		signObj.initVerify(publickey);
		signObj.update(inputMsg.getBytes());
		boolean isverified = signObj.verify(signbytes);
		
		System.out.println("is verified :"+isverified );
		System.out.println("public key:-" +Base64.getEncoder().encodeToString(publickey.getEncoded()));
		System.out.println("private key:-" +Base64.getEncoder().encodeToString(Pkey.getEncoded()));
		return encodeToString(Pkey.getEncoded());
	}

	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/Base64Encoding")
	public String encryptUsingBase64Encoding(@RequestParam int option, @RequestParam String inputMsg) throws Exception {
		Base64.Encoder base64encoder = Base64.getEncoder();
		String base64encodedStr = base64encoder.encodeToString(
		        inputMsg.getBytes(StandardCharsets.UTF_8) );
		System.out.println("Base64 encoded string:- "+base64encodedStr);
		Base64.Decoder base64decoder = Base64.getDecoder();
		byte[] decodedByteArray = base64decoder.decode(base64encodedStr);
		System.out.println("Base64 decoded string:- "+new String(decodedByteArray));
		return base64encodedStr;
	}
	@CrossOrigin(origins ="http://localhost:3000/")
	@GetMapping(path = "/Base64Decoding")
	public String encryptUsingBase64Decoding(@RequestParam int option, @RequestParam String inputMsg) throws Exception {
	
		Base64.Decoder base64decoder = Base64.getDecoder();
		byte[] decodedByteArray = base64decoder.decode(inputMsg);
		System.out.println("Base64 decoded string:- "+new String(decodedByteArray));
		return new String(decodedByteArray);
	}
	
	
	
	private static SecretKey generateSymmetricKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256, new SecureRandom());
		return keyGen.generateKey();
	}		

	private static IvParameterSpec generateIvParameter() {
		byte[] byteArray = new byte[16];
		SecureRandom random = new SecureRandom();
		random.nextBytes(byteArray);
		return new IvParameterSpec(byteArray);
	}
	
	private static KeyPair generateAsymmetricKey() throws Exception {
		return KeyPairGenerator.getInstance("RSA").generateKeyPair();
	}

	
	private static byte[] encodeMsg(Cipher cipher, SecretKey sKey, IvParameterSpec spec, String inputMsg)
			throws Exception {
		cipher.init(Cipher.ENCRYPT_MODE, sKey, spec);
		return cipher.doFinal(inputMsg.getBytes());
	}
	
	private static byte[] decodeMsg(Cipher cipher, SecretKey sKey, IvParameterSpec spec, byte[] encryptedMsg)
			throws Exception {
		cipher.init(Cipher.DECRYPT_MODE, sKey, spec);
		return cipher.doFinal(encryptedMsg);
	}
	
	private static String encodeToString(byte[] value) {
		return Base64.getEncoder().encodeToString(value);
	}

	
}
