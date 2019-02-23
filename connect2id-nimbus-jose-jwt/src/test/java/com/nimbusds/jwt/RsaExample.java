package com.nimbusds.jwt;
import javax.crypto.Cipher;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RsaExample { //This is not for JWT in Particular
	
	private static KeyStore clientKeyStore;
	  static private final String clientpassphrase = "clientpw";
	
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        //  keytool -genkeypair -alias mykey -storepass s3cr3t -keypass s3cr3t -keyalg RSA -keystore keystore.jks
    	// This is not use, and it can substitute the other generation method.
        InputStream ins = RsaExample.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("mykey", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("mykey");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static KeyPair getKeyPairFromFile() throws Exception {//Added by me to use files
        clientKeyStore = KeyStore.getInstance( "JKS" );
        clientKeyStore.load( new FileInputStream( "C:\\Users\\ID126219\\OneDrive - Birmingham City University\\Coding\\eclipse-workspace\\connect2id-nimbus-jose-jwt\\src\\test\\java\\com\\nimbusds\\jwt\\client.public" ),
                           "public".toCharArray() );
        clientKeyStore.load( new FileInputStream( "C:\\Users\\ID126219\\OneDrive - Birmingham City University\\Coding\\eclipse-workspace\\connect2id-nimbus-jose-jwt\\src\\test\\java\\com\\nimbusds\\jwt\\client.private" ),
                clientpassphrase.toCharArray() );
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("clientpw".toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) clientKeyStore.getEntry("clientprivate", keyPassword);
        java.security.cert.Certificate cert = clientKeyStore.getCertificate("clientprivate");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        return new KeyPair(publicKey, privateKey);
    }
    
    
    
    public static void PrintSplit(String S) {//Splitting array to chunks of 256 char
    	for (int i = 0; i < S.length(); i += 256) {
    		  System.out.println(S.substring(i, Math.min(i + 256, S.length())));
    		}
    }
    
    
	
public static ArrayList<String> Split_to_List(String S) {	 ArrayList<String> list = new ArrayList<String>();
	for (int i = 0; i < S.length(); i += 256) {
		list.add(S.substring(i, Math.min(i + 256, S.length())));
		}
	
		return list;
	}

public static String[] encrypt_long(ArrayList<String> plainText, PublicKey publicKey) throws Exception {
	String[] Enc_block=new String[plainText.size()];
	for (int i = 0; i < plainText.size(); i++) {
		Enc_block[i]=encrypt(plainText.get(i), publicKey);
		System.out.println(Enc_block[i]);
	}
	
	return Enc_block;
    
}

public static String[] decrypt_long(String[] encyptedArray, PrivateKey privateKey) throws Exception {
	String[] decryptedArray=new String[encyptedArray.length];
	for (int i = 0; i < encyptedArray.length; i++) {
		decryptedArray[i]=decrypt(encyptedArray[i], privateKey).trim();
		System.out.println(decryptedArray[i]);
	}
	
	return decryptedArray;
    
}
public static String ArraytoString(String[] strArray) {
	String combine="";
	for(int i=0; i<strArray.length; i++) {
		combine+=strArray[i];
	}
	return combine;
}
    
    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NoPadding");//("RSA");("RSA/ECB/PKCS1Padding");("RSA/ECB/NoPadding");<==
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA/ECB/NoPadding");//("RSA/ECB/NoPadding");//("RSA");("RSA/ECB/NoPadding");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public static void main(String... argv) throws Exception {
        //First generate a public/private key pair
       // KeyPair pair = generateKeyPair();
        //KeyPair pair = getKeyPairFromKeyStore();
    	KeyPair pair =getKeyPairFromFile();
        //Our secret message
       /*256*/ //String message = "the answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjj";
    	/*512*/ //String message = "the answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjjthe answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjj"; 
    	/*1024*/ String message = "1the answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjjthe answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjjthe answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjjthe answer to life the universe and everything the answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer to life the universe and everythingthe answer tdjkjjjjjjjjjj";
    	System.out.println(Split_to_List(message).size());
    	String[] encryptedArray=encrypt_long(Split_to_List(message), pair.getPublic());
        
    	String[] decryptedArray=decrypt_long(encryptedArray, pair.getPrivate());
    	
    	if(message.equals(ArraytoString(decryptedArray))) System.out.println("Bingo");
    	
    	/*//Encrypt the message
        String cipherText = encrypt(message, pair.getPublic());System.out.println("cipherText 1 "+cipherText);
        String cipherText2 = encrypt(message, pair.getPublic());System.out.println("cipherText 2 "+cipherText2);
        if(cipherText.equals(cipherText2)) System.out.println("Same Ciphers");

        
        //Now decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());

        System.out.println("Decyphered: "+decipheredMessage);
        //Let's sign our message
        String signature = sign("foobar", pair.getPrivate());

        //Let's check the signature
        boolean isCorrect = verify("foobar", signature, pair.getPublic());
        System.out.println("Signature correct: " + isCorrect);*/
    }
}
