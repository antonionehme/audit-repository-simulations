package audit.common.domain;


import com.google.common.primitives.Longs;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;

import java.util.Arrays;

public class Transaction {



    private byte[] hash;

    /**
     * Payload of this transaction
     */
    private String cipher;

    /**
     * The hash of the address which is responsible for this Transaction
     */
    private byte[] senderHash;

    /**
     * Signature of text which can be verified with publicKey of sender address
     */
    private byte[] signature;
    private String LocalDigest;//added digest

    /**
     * Creation time of this Transaction
     */
    private long timestamp;

    public Transaction() {
    }

    public Transaction(String cipher, byte[] senderHash, byte[] signature) {
        this.cipher = cipher;
        this.senderHash = senderHash;
        this.signature = signature;
        this.timestamp = System.currentTimeMillis();
        this.hash = calculateHash();
        this.LocalDigest="DIgest goes here.";
    }
    
    public Transaction(String cipher, byte[] senderHash, byte[] signature, String LocalDigest) {
        this.cipher = cipher;
        this.senderHash = senderHash;
        this.signature = signature;
        this.timestamp = System.currentTimeMillis();
        this.hash = calculateHash();
        this.LocalDigest=LocalDigest;
    }

  /*  public String toString() {
    	return "test";
    }*/
    public byte[] getHash() {
        return hash;
    }

    public void setHash(byte[] hash) {
        this.hash = hash;
    }

    public String getcipher() { 
        return cipher;
    }   
    
    public String getLocalDigest() { //return "Antonio";
        return LocalDigest;
    }
    
    public void setLocalDigest(String LocalDigest) {
        this.LocalDigest = LocalDigest;
    }



    public void setcipher(String cipher) {
        this.cipher = cipher;
    }

    public byte[] getSenderHash() {
        return senderHash;
    }

    public void setSenderHash(byte[] senderHash) {
        this.senderHash = senderHash;
    }

    public byte[] getSignature() {
        return signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getSignableData() {
        return cipher.getBytes();
    }

    /**
     * Calculates the hash using relevant fields of this type
     * @return SHA256-hash as raw bytes
     */
    public byte[] calculateHash() {
        byte[] hashableData = ArrayUtils.addAll(cipher.getBytes(), senderHash);
        hashableData = ArrayUtils.addAll(hashableData, signature);
        hashableData = ArrayUtils.addAll(hashableData, Longs.toByteArray(timestamp));
        return DigestUtils.sha256(hashableData);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        Transaction that = (Transaction) o;

        return Arrays.equals(hash, that.hash);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(hash);
    }
}
