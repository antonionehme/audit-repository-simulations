package com.nimbusds.jwt;


import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import junit.framework.TestCase;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;


public class SignedJWTClass {

	public static void testNestedTokens() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSetOne = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSSigner signer = new RSASSASigner(privateKey);
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetOne);
		signedJWT.sign(signer);
		String orderOne = signedJWT.serialize();

		//System.out.println(claimsSetOne.toString());
		System.out.println(claimsSetOne.toJSONObject());
		
		JWTClaimsSet claimsSetTwo = new JWTClaimsSet.Builder()
			.subject("alice")
			.issuer("https://c2id.com")
			.issueTime(new Date(123000L))
			.claim("scope", "openid")
			.claim("JWTONE", orderOne)
			.build();

		signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSetTwo);
		signedJWT.sign(signer);
		String orderTwo = signedJWT.serialize();
		System.out.println(claimsSetTwo.toJSONObject());
		//System.out.println(claimsSetTwo.toJSONObject().get("JWTONE"));
		// assertNotSame(orderOne, orderTwo);
	}

	public static void testSignAndVerify()
		throws Exception {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);

		KeyPair kp = kpg.genKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.issueTime(new Date(123000L))
			.issuer("https://c2id.com")
			.claim("scope", "openid")
			.build();

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256).
			keyID("1").
			jwkURL(new URI("https://c2id.com/jwks.json")).
			build();

		SignedJWT signedJWT = new SignedJWT(header, claimsSet);

/*		assertEquals(JWSObject.State.UNSIGNED, signedJWT.getState());
		assertEquals(header, signedJWT.getHeader());
		assertEquals("alice", signedJWT.getJWTClaimsSet().getSubject());
		assertEquals(123000L, signedJWT.getJWTClaimsSet().getIssueTime().getTime());
		assertEquals("https://c2id.com", signedJWT.getJWTClaimsSet().getIssuer());
		assertEquals("openid", signedJWT.getJWTClaimsSet().getStringClaim("scope"));
		assertNull(signedJWT.getSignature());
*/
		Base64URL sigInput = Base64URL.encode(signedJWT.getSigningInput());

		JWSSigner signer = new RSASSASigner(privateKey);

		signedJWT.sign(signer);

/*		assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
		assertNotNull(signedJWT.getSignature());
*/
		String serializedJWT = signedJWT.serialize();

		signedJWT = SignedJWT.parse(serializedJWT);
		System.out.println(signedJWT.getParsedString());
		//assertEquals(serializedJWT, signedJWT.getParsedString());

		//assertEquals(JWSObject.State.SIGNED, signedJWT.getState());
		//assertNotNull(signedJWT.getSignature());
		//assertTrue(sigInput.equals(Base64URL.encode(signedJWT.getSigningInput())));

		JWSVerifier verifier = new RSASSAVerifier(publicKey);
		//assertTrue(signedJWT.verify(verifier));
	}
	
	
	public void testTrimWhitespace()
		throws Exception {
		
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
		jwt.sign(new MACSigner(secret));
		
		String jwtString = " " + jwt.serialize() + " ";
		
		jwt = SignedJWT.parse(jwtString);
		// assertTrue(jwt.verify(new MACVerifier(secret)));
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
	public void testSignedJWTWithNullClaimValue()
		throws Exception {
		
		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.claim("myclaim", null)
			.build();
		
		JWSObject jwsObject = new JWSObject(
			new JWSHeader(JWSAlgorithm.HS256),
			new Payload(claimsSet.toJSONObject(true))
		);
		
		jwsObject.sign(new MACSigner(secret));
		
		SignedJWT jwt = SignedJWT.parse(jwsObject.serialize());
		//assertTrue(jwt.verify(new MACVerifier(secret)));
		
		claimsSet = jwt.getJWTClaimsSet();
		//assertEquals("alice", claimsSet.getSubject());
		//assertNull(claimsSet.getClaim("myclaim"));
		//assertTrue(claimsSet.getClaims().containsKey("myclaim"));
		//assertEquals(2, claimsSet.getClaims().size());
	}
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			testNestedTokens();
			testSignAndVerify();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
