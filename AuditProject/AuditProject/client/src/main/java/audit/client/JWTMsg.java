package audit.client;

//import java.io.InputStream;
import java.io.*;
import java.math.BigInteger;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.crypto.*;
import junit.framework.TestCase;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;

/*These are the RSA libraries*/
import javax.crypto.Cipher;

import java.security.*;
import java.util.Base64;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import javax.net.*;
import javax.net.ssl.*;

import org.apache.commons.codec.digest.DigestUtils;

import static java.nio.charset.StandardCharsets.UTF_8;


public class JWTMsg {
//I think we can use JWE for inter-party communications, and Deterministic RSA for the audit trail.
	
	private static KeyStore clientKeyStore;
	  static private final String clientpassphrase = "clientpw";
	  static private final String serverpassphrase = "serverpw";
	  
	  private String Data, Iss, Rec, Label;
	  private String[] Prev, ParaPrev;
	  
	  public JWTMsg() {
		  
	  }
		public JWTMsg(String Data, String Iss, String Rec, String Label, String[] Prev, String[] ParaPrev) {
			this.Data=Data;
			this.Iss=Iss;
			this.Rec=Rec;
			this.Label=Label;
			this.Prev=Prev;
			this.ParaPrev=ParaPrev;
		}
		
		//Added this in order to be able not to add ParaPrev.
		public JWTMsg(String Data, String Iss, String Rec, String Label, String[] Prev) {
			this.Data=Data;
			this.Iss=Iss;
			this.Rec=Rec;
			this.Label=Label;
			this.Prev=Prev;
			//this.ParaPrev=ParaPrev;
		}
		
		public JWTMsg(String toParse) throws net.minidev.json.parser.ParseException, JsonProcessingException, IOException {
		JSONParser parser = new JSONParser(); 
		JSONObject json = (JSONObject) parser.parse(toParse);
		
		//json.getAsString(key)
		this.Data=json.getAsString("Data");
		this.Iss=json.getAsString("iss");
		this.Rec=json.getAsString("Rec");
		this.Label=json.getAsString("Label");
		//Get Prev as string and parse it
		//PPrev and ParaPred are CypherTextx.
		String PrevParser=json.get("Prev").toString();
		PrevParser=PrevParser.substring(2, PrevParser.length()-2);
		String[] parts = PrevParser.split("\",\"");
		this.Prev=parts;
		
		String ParaPrevParser=json.get("ParaPrev").toString();
		ParaPrevParser=ParaPrevParser.substring(2, ParaPrevParser.length()-2);
		String[] ParaParts = ParaPrevParser.split("\",\"");
		this.ParaPrev=ParaParts;
		
		//this.ParaPrev=(String[]) json.get("ParaPrev");
		}
		

		public String getData() {
			return Data;
		}

		public void setData(String data) {
			Data = data;
		}

		public String getIss() {
			return Iss;
		}

		public void setIss(String iss) {
			Iss = iss;
		}

		public String getRec() {
			return Rec;
		}

		public void setRec(String rec) {
			Rec = rec;
		}

		public String getLabel() {
			return Label;
		}

		public void setLabel(String label) {
			Label = label;
		}

		public String[] getPrev() {
			return Prev;
		}

		public void setPrev(String[] prev) {
			Prev = prev;
		}

		public String[] getParaPrev() {
			return ParaPrev;
		}

		public void setParaPrev(String[] paraPrev) {
			ParaPrev = paraPrev;
		}
		
		public static JWTClaimsSet Build_JWT(JWTMsg msg){
			String Data=msg.getData();
			String Iss = msg.getIss();
			String Rec = msg.getRec();
			String Label = msg.getLabel();
			List<String> aud = new ArrayList<>();
			aud.add("https://app-one.com");
			aud.add("https://app-two.com");
			final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
			Date exp = new Date(NOW.getTime() + 1000*60*10);
			Date nbf = NOW;
			Date iat = NOW;
			String jti = UUID.randomUUID().toString();


			JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().
				claim("Data",Data).
				issuer(Iss).
				claim("Rec", Rec).
				claim("Label", msg.getLabel()).
				claim("Prev",msg.getPrev()).
				claim("ParaPrev",msg.getParaPrev()).
				//jwtID(jti).
				build();
			return jwtClaims;
}
		
		public static String Plain_JWT(JWTMsg msg) {
	return ""+Build_JWT(msg);
		}
		


		public static String Enc_JWT(JWTMsg msg, RSAPublicKey publicKey) 
				throws Exception {
				JWTClaimsSet jwtClaims = Build_JWT(msg);
				
				// Request JWT encrypted with RSA-OAEP and 128-bit AES/GCM
				JWEHeader headerAudit = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
				//let's keep in mind that we need to sign before encryption.

				// Create the encrypted JWT object
				EncryptedJWT jwtAudit = new EncryptedJWT(headerAudit, jwtClaims);
				//IF encrypting different 
				//System.out.println(jwt.getHeader());
				
				//System.out.println(jwtClaims.toJSONObject());

				// Create an encrypter with the specified public RSA key
				RSAEncrypter encrypter = new RSAEncrypter(publicKey);
				encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

				// Do the actual encryption
				jwtAudit.encrypt(encrypter);
				// After reaching this stage, we add the entire JWE as a claim (that is encrypted for audit), and we redo it with another encryption for the receiver.
				// Each receiver can decrypt the audit and pass it along.
				// How efficient is this? Let's say 5 steps here would require a 5 times decryption from audit.
				

				// Serialise to JWT compact form
				String jwtString = jwtAudit.serialize();
				//System.out.println("Encrypted JWT: "+jwtString);
				return jwtString;
					}
		
		
		

		/*public static String Enc_JWT(JWTMsg msg, byte[] publicKeybytes) {//Read RSAPublicKey from file.
			throws Exception {
			
			PublicKey publicKey = 
    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
    
				JWTClaimsSet jwtClaims = Build_JWT(msg);
				
				// Request JWT encrypted with RSA-OAEP and 128-bit AES/GCM
				JWEHeader headerAudit = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
				//let's keep in mind that we need to sign before encryption.

				// Create the encrypted JWT object
				EncryptedJWT jwtAudit = new EncryptedJWT(headerAudit, jwtClaims);
				//IF encrypting different 
				//System.out.println(jwt.getHeader());
				
				//System.out.println(jwtClaims.toJSONObject());

				// Create an encrypter with the specified public RSA key
				RSAEncrypter encrypter = new RSAEncrypter(publicKey);
				encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

				// Do the actual encryption
				jwtAudit.encrypt(encrypter);
				// After reaching this stage, we add the entire JWE as a claim (that is encrypted for audit), and we redo it with another encryption for the receiver.
				// Each receiver can decrypt the audit and pass it along.
				// How efficient is this? Let's say 5 steps here would require a 5 times decryption from audit.
				

				// Serialise to JWT compact form
				String jwtString = jwtAudit.serialize();
				System.out.println("Encrypted JWT: "+jwtString);
				return jwtString;
					}*/

		
		public static String Dec_JWT(String EncJWT, RSAPrivateKey privateKey) throws ParseException {
		EncryptedJWT RecoveredJWT = null;
		try {
			RecoveredJWT = EncryptedJWT.parse(EncJWT);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		RSADecrypter decrypter = new RSADecrypter(privateKey);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		try {
			RecoveredJWT.decrypt(decrypter);
		} catch (JOSEException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//System.out.println("Decrypted "+ RecoveredJWT.getJWTClaimsSet());
		return RecoveredJWT.getJWTClaimsSet().toString();
		}
		

	
    public static KeyPair getKeyPairFromFile(String client, String pass, String passphrase, String alias) throws Exception {//Added by me to use files
        clientKeyStore = KeyStore.getInstance( "JKS" );
        clientKeyStore.load( new FileInputStream( "C:\\Users\\ID126219\\OneDrive - Birmingham City University\\Coding\\eclipse-worspace-audit-paper3\\AuditProject\\AuditProject\\client\\src\\main\\java\\audit\\client\\"+client+".public" ),
                           "public".toCharArray() );
        /*clientKeyStore.load( new FileInputStream( "C:\\Users\\ID126219\\OneDrive - Birmingham City University\\Coding\\eclipse-workspace-audit-paper\\AuditProject\\AuditProject\\client\\src\\main\\java\\audit\\client\\"+client+".public" ),
                "pub".toCharArray() );//change from .public to .pub */

        clientKeyStore.load( new FileInputStream( "C:\\Users\\ID126219\\OneDrive - Birmingham City University\\Coding\\eclipse-worspace-audit-paper3\\AuditProject\\AuditProject\\client\\src\\main\\java\\audit\\client\\"+client+".private" ),
              passphrase.toCharArray() );//clientpassphrase.toCharArray() ); changed from private to priv
       
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection(pass.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) clientKeyStore.getEntry(alias, keyPassword);
        java.security.cert.Certificate cert = clientKeyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        return new KeyPair(publicKey, privateKey);
    }
    
 /*  https://community.oracle.com/thread/1528259?start=0&tstart=0
  *  public static RSAPrivateKey getPrivateKeyFromFile(String Path) {
    	Files.readAllBytes(Paths.get("client.priv"));
 //   File pubKeyFile = 
    File privKeyFile = new File(Path);
    	

    // read public key DER file
     DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
     byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
     dis.readFully(privKeyBytes);
     dis.close();
     
   
     // decode private key
     PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
     RSAPrivateKey privKey = (RSAPrivateKey) KeyFactory.generatePrivate(privSpec);
     
    }*/
    
/*This is the RSA part*/
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    public static void PrintSplit(String S) {//Splitting array to chunks with a max size of 256 chars
    	for (int i = 0; i < S.length(); i += 256) {
    		  System.out.println(S.substring(i, Math.min(i + 256, S.length())));
    		}
    }
    
    
    public static String CleanReceivedPrevForVerification(String Prev) {// Java replaces / with \/ or \\/ in the string for some reason
    	String ret= Prev.replaceAll("\\\\/", "/");
    	return ret;
    	
    }
	
public static ArrayList<String> Split_to_List(String S) {	//we are using 2048 bit keys.
	ArrayList<String> list = new ArrayList<String>();
	for (int i = 0; i < S.length(); i += 256) {
		list.add(S.substring(i, Math.min(i + 256, S.length())));
		}
	
		return list;
	}

public static String[] encrypt_long(ArrayList<String> plainText, PublicKey publicKey) throws Exception {
	String[] Enc_block=new String[plainText.size()];
	for (int i = 0; i < plainText.size(); i++) {
		Enc_block[i]=encrypt(plainText.get(i), publicKey);
		//System.out.println(Enc_block[i]);
	}
	
	return Enc_block;
    
}

public static String[] decrypt_long(String[] encyptedArray, PrivateKey privateKey) throws Exception {
	String[] decryptedArray=new String[encyptedArray.length];
	for (int i = 0; i < encyptedArray.length; i++) {
		decryptedArray[i]=decrypt(encyptedArray[i], privateKey).trim();
		//System.out.println(decryptedArray[i]);
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

public static String ArraytoStringCleanCut(String[] strArray) { 
	//Combines an array in a string with "|||" used for separation. This is to keep track of the encrypted blocks.
	String combine="";
	for(int i=0; i<strArray.length; i++) {
		if(i==0) {combine+=strArray[i];}
		else {combine=combine+"xyz123"+ strArray[i];}// Fixed this.
	}
	return combine;
}

public static String[] StringCleanCuttoArray(String str) {
	//Split string at |||.
	String[] ret=str.split("xyz123");
	return ret;
}

public static String[] StringtoArray(String str) {
	/* I added this in order to be able to decrypt long arrays. */
	ArrayList<String> list = new ArrayList<String>();
	for (int i = 0; i < str.length(); i += 256) {
		list.add(str.substring(i, Math.min(i + 256, str.length())));
		}
	
	String[] stringArray = list.toArray(new String[0]);	
		
	return stringArray;
	
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
    //////////////////////////////////////////////////////////////////////////////////////////////////////////////////


	
	public static void main(String[] args) throws Exception {

		KeyPair receiverPair =getKeyPairFromFile("client3", "clientpw", clientpassphrase, "clientprivate");
		KeyPair auditPair =getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate");
		JWTMsg msg=new JWTMsg("Data", "Issuer", "Recipient", "Label", new String[] {"Prev1", "Prev2"}, new String[] {"ParaPrev1", "ParaPrev2"});
		
		
		String JWTEncMsg= Enc_JWT(msg,(RSAPublicKey)receiverPair.getPublic());
		String DecJWT= Dec_JWT(JWTEncMsg, (RSAPrivateKey)receiverPair.getPrivate());
		if (Plain_JWT(msg).equals(DecJWT))System.out.println("Plain and Dec are the same");
		else {
			System.out.println("They are not");	
		}
		
		System.out.println("PlainJWT "+ Plain_JWT(msg).toString());
		if (Plain_JWT(msg).equals(DecJWT))System.out.println("Bingo 1");
		
		String msgString=ArraytoString(encrypt_long(Split_to_List(Plain_JWT(msg)), auditPair.getPublic()));
		String forAudit=ArraytoString(encrypt_long(Split_to_List(DecJWT), auditPair.getPublic()));
		if (msgString.equals(forAudit))System.out.println("Bingo v");
		  
		//private static byte[] calculateLocalHash() {
	        String hashableData = "test		"
	        		+ "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD";
	        
	        System.out.println(DigestUtils.sha256(hashableData));
	        
	        String str = "Example String";
	        byte[] b = str.getBytes();
	        System.out.println("Array " + b);
	        System.out.println("Array as String" + Arrays.toString(b));
		
		/*now his is what gets submitted to audit*/
		
		
	}


}
