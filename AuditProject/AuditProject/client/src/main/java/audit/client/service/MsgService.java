package audit.client.service;


import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import audit.common.SignatureUtils;
import audit.common.domain.Address;
import audit.common.domain.Node;
import audit.common.domain.Transaction;
import audit.client.*;

import java.util.*;


@Service
public class MsgService{

    private final static Logger LOG = LoggerFactory.getLogger(MsgService.class);

  //  private final AddressService addressService;


    /**
     * Pool of Transactions which are not included in a Block yet.
     */
    private static Set<String> msgPool = new HashSet<>();//added the static to get from JWTClientandService
    // This is where Messages are stored.
    private static List<String> postedAuditRecs = new ArrayList<>();
    //myposted audit recs
    private static List<String> storedAuditRecs = new ArrayList<>();//we're making a difference between posted, pulled, and stored audit recs.
    //Where audit recs are stored
    
    @Autowired
    public MsgService() {//public TransactionService(AddressService addressService) {
      //  this.addressService = addressService;
    }


    public static Set<String> getmsgPool() {//added the static to get from JWTClientandService
        return msgPool;
    }
    
    public static List<String> getStoredAuditRecs() {//added the static to get from JWTClientandService
        return storedAuditRecs;
    }
    
    public static List<String> getPostedAuditRecs() {//added the static to get from JWTClientandService
        return postedAuditRecs;
    }

    public static void setStoredAuditRecs(List<String> toset) {//added the static to get from JWTClientandService
    	storedAuditRecs=toset;
    }
    public static void addStoredAuditRec(String rec) {
    	storedAuditRecs.add(rec);
    }
    
    public static void addPostedAuditRec(String rec) {
    	postedAuditRecs.add(rec);
    }
    
    /**
     * Add a new Transaction to the pool
     * @param transaction Transaction to add
     * @return true if verification succeeds and Transaction was added
     */
    public synchronized boolean add(String transaction) {
    	//AuditRecordverification(transaction);
            msgPool.add(transaction);
            //Here, we trigger the audit rec verification.
            return true;
       
    }

    /**
     * Remove Transaction from pool
     * @param transaction Transaction to remove
     */
    public void remove(String transaction) {
        msgPool.remove(transaction);
    }

    /**
     * Does the pool contain all given Transactions?
     * @param transactions Collection of Transactions to check
     * @return true if all Transactions are member of the pool
     */
    public boolean containsAll(Collection<String> transactions) {
        return msgPool.containsAll(transactions);
    }

  
  
}
