package audit.server.service;


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

import java.util.*;


@Service
public class TransactionService {

    private final static Logger LOG = LoggerFactory.getLogger(TransactionService.class);

    private final AddressService addressService;


    /**
     * Pool of Transactions which are not included in a Block yet.
     */
    private static List<Transaction> transactionPool = new ArrayList<>();//chaged to static
    //===> Changed from hashmap to arraylist
    // This is where transactions are stored.
    
    @Autowired
    public TransactionService(AddressService addressService) {
        this.addressService = addressService;
    }


    public List<Transaction> getTransactionPool() {
        return transactionPool;
    }

    /**
     * Add a new Transaction to the pool
     * @param transaction Transaction to add
     * @return true if verifcation succeeds and Transaction was added
     */
    public synchronized boolean add(Transaction transaction) {
        if (verify(transaction)) {
            transactionPool.add(transaction);
            return true;
        }
        return false;
    }
    


    /**
     * Remove Transaction from pool
     * @param transaction Transaction to remove
     */
    
    public static void removefirst() {//had to add this.
    	transactionPool.remove(transactionPool.toArray(new Transaction[transactionPool.size()])[0]);
    }
    public static void removeAll() {//had to add this.
    	transactionPool.clear();
    }
    
    public void remove(Transaction transaction) {
        transactionPool.remove(transaction);
    }

    /**
     * Does the pool contain all given Transactions?
     * @param transactions Collection of Transactions to check
     * @return true if all Transactions are member of the pool
     */
    public boolean containsAll(Collection<Transaction> transactions) {
        return transactionPool.containsAll(transactions);
    }

    private boolean verify(Transaction transaction) {
        // correct signature
        Address sender = addressService.getByHash(transaction.getSenderHash());
        if (sender == null) {
            LOG.warn("Unknown address " + Base64.encodeBase64String(transaction.getSenderHash()));
            return false;
        }

        try { //signable data is the text/cioher
            if (!SignatureUtils.verify(transaction.getSignableData(), transaction.getSignature(), sender.getPublicKey())) {
                //Checks the signature of the sender, and verifies it with the sender's public key
            	LOG.warn("Invalid signature");
                return false;
            }
        } catch (Exception e) {
            LOG.error("Error while verification", e);
            return false;
        }

        // correct hash
        if (!Arrays.equals(transaction.getHash(), transaction.calculateHash())) {
            LOG.warn("Invalid hash");
            return false;
        }

        return true;
    }

    /**
     * Download Transactions from other Node and them to the pool
     * @param node Node to query
     * @param restTemplate RestTemplate to use
     */
    public void retrieveTransactions(Node node, RestTemplate restTemplate) {
        Transaction[] transactions = restTemplate.getForObject(node.getAddress() + "/transaction", Transaction[].class);
        Collections.addAll(transactionPool, transactions);
        LOG.info("Retrieved " + transactions.length + " transactions from node " + node.getAddress());
    }
}
