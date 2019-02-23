package audit.client;


import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.json.JSONObject;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.client.RestTemplate;

import com.google.api.client.util.Maps;
import com.nimbusds.jwt.JWTClaimsSet;

import audit.client.JWTMsg;
import audit.client.service.MsgService;
import audit.common.SignatureUtils;
import audit.common.domain.Address;
import audit.common.domain.Transaction;

import java.io.BufferedReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

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
import java.util.concurrent.TimeUnit;
import java.util.Random;



/**
 * Simple class to help building REST calls for jBlockchain.
 * Just run it in command line for instructions on how to use it.
 *
 * Functions include:
 * - Generate Private/Public-Key
 * - Publish a new Address
 * - Publish a new Transaction
 */

@Service
@SpringBootApplication //Added this for the web service.
public class WorkflowGenericParticipant2Ports {//Added the extension hoping to get the service variables
	 private static KeyStore clientKeyStore;
	  static private final String clientpassphrase = "clientpw";
	  static private final String serverpassphrase = "serverpw";
	  private static List<String> pulledAuditRecs = new ArrayList<>(); 
	  private static List<String> AuditRecsforReceivedMessages = new ArrayList<>();
	  private static List<Long> pulledAuditRecsReportingTime = new ArrayList<>();
	  private static Long mostRecentReportingTime;//of an audit record by any participant
	  private static String mostRecentAuditRecord; //published on the audit server by any participant. THis is because elements in a hashmap are not in order.
	  private static String mostRecentReportedLocalHash;// LocalHash Values Reported by other clients to the audit server.
	  private static Long epsilon=(long) 100.0;
	  // These are added for the command line options
	  static String file_send = "data_send.csv"; static String file_recieve = "data_receive.csv";
	  private static String addresstoPublish="";
	  private static String port="";
	  private static String name="";
	  private static String recipientPort= "";
	  
    public static void main(String args[]) throws Exception {
    	/*String str="s1vjwh1gQl1scMrAFkM0KDV2E9m7hr7+oW2P1OCfVSk7NIEE9d\\/jPB2c\\/QV9QtMmpOqXl0\\/rIMEvaCSSO7+kM1gpScdW4b88V0HogFvbZbE91A9IwrOpz5qJCzWNd9H\\/zdVbv6AI4AS1AXInZMcuKjZukSQxCHUXuzO34GB445Ypti5mcyrnphW20nagBs\\/kPcYYAtEszb0MxkOpq2YSdw2lU\\/O\\/fO7qFz0Qruj3BlpuVXIrJ64s4R0rjMr9fLUenlHTgTEqKZDql+gwZT48IahtxAztwENa01rvJz2reWFluhlIJMeN6e2ZIT3JMvWUh6pOBgy\\/pINQmgqpd\\/pBbg==";
    	System.out.println("After Cleaning "+str.replaceAll("\\\\/", "/"));
    	
    	JWTMsg msg=new JWTMsg("Data", "Issuer", "Recipient", "Label", new String[] {"Prev1", "Prev2"}, new String[] {"ParaPrev1", "ParaPrev2"});
    	JWTMsg msg2=new JWTMsg(msg.Plain_JWT(msg));
    	System.out.println("First: "+msg.Plain_JWT(msg));
    	System.out.println("Second: "+msg2.Plain_JWT(msg2));*/
    	  //Turning this to a service
    	
    	CommandLineParser parser = new DefaultParser();
        Options options = getOptions();
        try {
            CommandLine line = parser.parse(options, args);
            executeCommand(line);//posting forAudit on the wall.
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("BlockchainClient", options , true);
        }
    	
        SpringApplication app = new SpringApplication(WorkflowGenericParticipant2Ports.class);
        Map<String, Object> pro = Maps.newHashMap();
        pro.put("server.port", port);

        app.setDefaultProperties(pro);
        app.run(args);
        System.out.println(port+ " "+ name+" "+ recipientPort);
        
    	
        //SendingandVerifyingMessagesandAuditRecs();
       // SendingandVerifyingMessagesandAuditRecsWithKeyFiles(Paths.get("client.priv"),Paths.get("client.public"),Paths.get("key.private"),Paths.get("key.pub"));
        
       // publishAddress("key.pub", "Antonio Nehme");
        //UseCommandLineOptions(); Need to copy the body and copy it to the main if this is to be used.

       // pullAudits(); 
        switchOptions();
    }
  
    private static void executeCommand(CommandLine line) throws Exception {//This does not consider what's fed from the command line for the message.

        String p = line.getOptionValue("port");
        String n = line.getOptionValue("name");
        String rp = line.getOptionValue("recipientPort");
      //  String r= line.getOptionValue("recipient");
        if (port == null || name == null|| recipientPort == null) {
            throw new ParseException("Missing Arguments");
        }
        port=p;
        name=n;
        //int i = Integer.parseInt(port.trim());
        //i=i+1;
        recipientPort=""+rp;
        //publishTransaction(new URL(node), Paths.get(privatekey), message, Base64.decodeBase64(sender), "This is the Local Hash");
    
}
    private static Options getOptions() {
        OptionGroup actions = new OptionGroup();
        actions.addOption(new Option("a", "arguments", false, "Please pass the arguments"));
        actions.setRequired(true);

        Options options = new Options();
        options.addOptionGroup(actions);
        options.addOption(Option.builder("p")
                .longOpt("port")
                .hasArg()
                .argName("Port Number")
                .desc("needed to run the service")
                .build());
        options.addOption(Option.builder("n")
                .longOpt("name")
                .hasArg()
                .argName("name of the sender")
                .desc("needed to recognize the sender- publish name on the server- print on receipt")
                .build());
        options.addOption(Option.builder("rp")
                .longOpt("recipientPort")
                .hasArg()
                .argName("Port of the Receiver")
                .desc("needed to recognize the address of the Receiver")
                .build());
        

        return options;
    }
  
    
    //////////////////////////From MSGService/////////////////////
    
    private final static Logger LOG = LoggerFactory.getLogger(MsgService.class);



     // private static Set<String> msgPool = new HashSet<>();//added the static to get from JWTClientandService
      private static List<String> msgPool = new ArrayList<>(); //Changing from Hashset to List.
      // This is where Messages are stored.
      private static List<String> postedAuditRecs = new ArrayList<>();
      //myposted audit recs
      private static List<String> storedAuditRecs = new ArrayList<>();//we're making a difference between posted, pulled, and stored audit recs.
      //Where audit recs are stored
      
      @Autowired
      public WorkflowGenericParticipant2Ports() {//public TransactionService(AddressService addressService) {
        //  this.addressService = addressService;
      }


      public static List<String> getmsgPool() {// Messages received from another participant.
          return msgPool;
      }
      
      public static List<String> getStoredAuditRecs() {//Audit records that a participant gets from the server, and adds when publishing a transaction.
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
     * @throws Exception 
       */
      // public synchronized boolean add
      public synchronized boolean add(String message) throws Exception { //This is the method for a participant to receive a message.
    	  System.out.println("_____________Message Received by "+ name );
    	 
    	  FileWriter fileWriter_recieve = new FileWriter(file_recieve,true);
      	long startTime_recieve = System.currentTimeMillis();
      	
    	  boolean verif=EncryptedAuditRecordverification(message,"client2");//Here's where the problem is. When this is commented, the message gets received.
              msgPool.add(message);
         
        long endTime_recieve = System.currentTimeMillis(); long duration_recieve = (endTime_recieve - startTime_recieve);
        fileWriter_recieve.append(name+ " Receiving"+","+duration_recieve+"\n");
        fileWriter_recieve.flush();
        fileWriter_recieve.close();
             
              //Here, we trigger the audit rec verification. Added to automate the simulation.
              ///////////////////////////////////////This is case 4 //////////////////////////////////////
             /* pullAudits();//Added; not essential
              TimeUnit.SECONDS.sleep(1);
              Random rand = new Random();
              int n = rand.nextInt(500000) + 1;
              String dummyData = "Data"+n+""+System.currentTimeMillis();

              JWTMsg msg=new JWTMsg(dummyData, "Issuer", "Recipient", "Label", new String[] {mostRecentAuditRecord}, new String[] {"ParaPrev1", "ParaPrev2"});
              
          	FileWriter fileWriter_send = new FileWriter(file_send,true);
          	long startTime_send = System.currentTimeMillis();
          	
              sendMessageToParticipant("http://localhost:"+recipientPort+"/participant?publish=true", msg, "key.priv", "HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=", "client2", "server");
             
              long endTime_send = System.currentTimeMillis();long duration_send = (endTime_send - startTime_send);
              fileWriter_send.append(name+","+duration_send+"\n");// this becomes like a loop...
              fileWriter_send.flush();
              fileWriter_send.close();*/
              //Not having the chance to close
              
//////////////////////////////////////end of Case 4//////////////////////////////////////
              
              //Here, we can directly send the message to the next participant.
              //if(verif)  sendMessageToParticipant("http://localhost:8095", msg, "key.priv", "0xbdXETP8nmHznzg34Xzd9P3mNmRlIC+MQEXoqe1aGs=", "client2", "server");
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
      
      ///////////////////////////////////////////////////////
      public static void switchOptions() throws Exception { Scanner scan=new Scanner(System.in);
    System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
    	String option=scan.nextLine();
    	while(option!="X") {
        switch(option) {
       /* case "AddRecord" :{ System.out.println("Adding an audit record to the client, but not the audit server");
        	addPostedAuditRec("Added Local Record");
           option=scan.nextLine();}
           break;*/
        case "0" :{
        publishAddress("key.pub", name);//publishAddress("key.pub", "Antonio Nehme");
        System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
        option=scan.nextLine();}
        break; 
        case "1" :{
        	AuditServerVerificartion();
            System.out.println(getStoredAuditRecs());
            System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
            option=scan.nextLine();}
            break;
        case "2" :{ 
        	System.out.println("mostRecentReportingTime "+mostRecentReportingTime+" mostRecentAuditRecord "+ mostRecentAuditRecord+ " mostRecentReportedLocalHash "+ mostRecentReportedLocalHash);
        	System.out.println("pulledAuditRecs "+pulledAuditRecs+" getStoredAuditRecs "+getStoredAuditRecs()+" getPostedAuditRecs "+getPostedAuditRecs());
        	if(pulledAuditRecs.equals(getStoredAuditRecs()))System.out.println("pulledAuditRecs and etStoredAuditRecs() are equal");
        	System.out.println("Arrays.toString(calculateLocalHash()) "+ Arrays.toString(calculateLocalHash()));
        	System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
        	option=scan.nextLine();}
        break;
        case "3": {
        	System.out.println("Add your message: "); String msg= scan.nextLine();
        System.out.println("Add your Address: "); String address= scan.nextLine();
        	publishAuditRecord("key.priv",msg,address);//
        	System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
        	option=scan.nextLine();
        }break;
        case "4": {System.out.println("0 to Add Address, 1 to VerifyServer, 2 to see last reported record on the audit server, 3 to Publish a message, 4 Send a message to another recipient, X to exit.");
       // publishAuditRecord("key.priv",postedAuditRecs.get(0),"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=");
        pullAudits();//Added; not essential
        TimeUnit.SECONDS.sleep(1); 
        Random rand = new Random();
        int n = rand.nextInt(500000) + 1;
        String dummyData = "Data"+n+""+System.currentTimeMillis();
        //JWTMsg msg=new JWTMsg(dummyData, name, "Recipient", "http://localhost:"+recipientPort, new String[] {mostRecentAuditRecord}, new String[] {"ParaPrev1", "ParaPrev2"});
        JWTMsg msg=new JWTMsg(dummyData, name, "Recipient", "http://localhost:"+recipientPort, ArraylistToArray(AuditRecsforReceivedMessages), new String[] {"ParaPrev1", "ParaPrev2"});
        
    	FileWriter fileWriter = new FileWriter(file_send,true);
    	long startTime = System.currentTimeMillis();
    	
        sendMessageToParticipant("http://localhost:"+recipientPort+"/node?publish=true", msg, "key.priv", "HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=", "client2", "server");
       
        long endTime = System.currentTimeMillis();long duration = (endTime - startTime);
        fileWriter.append(name+ " to "+recipientPort +","+duration+"\n");
    	fileWriter.flush();
        fileWriter.close();
        	option=scan.nextLine();
        }break;
        
        default :{
           System.out.println("Invalid Option");
           option=scan.nextLine();}
     }
        }
     
  }
      
    public static void UseCommandLineOptions() {
   /* CommandLineParser parser = new DefaultParser();
    Options options = getOptions();
    try {
        CommandLine line = parser.parse(options, args);
        executeCommand(line, "Audit data");//posting forAudit on the wall.
    } catch (ParseException e) {
        System.err.println(e.getMessage());
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("BlockchainClient", options , true);
    }*/
    }
    
    
    
    public static void SendingandVerifyingMessagesandAuditRecs() throws Exception { // This is only reference for JWT cipher methods and verifications. 
    	//We are calling JWT methods using the JWTMsg object.
    	// 
    	JWTMsg msg=new JWTMsg("Data", "Issuer", "Recipient", "Label", new String[] {"Prev1", "Prev2"}, new String[] {"ParaPrev1", "ParaPrev2"});
    	KeyPair receiverPair =msg.getKeyPairFromFile("client3", "clientpw", clientpassphrase, "clientprivate");
		KeyPair auditPair =msg.getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate");
		
		
		
		String JWTEncMsg= msg.Enc_JWT(msg,(RSAPublicKey)receiverPair.getPublic());
		String DecJWT= msg.Dec_JWT(JWTEncMsg, (RSAPrivateKey)receiverPair.getPrivate());
		System.out.println("Plain JWT: "+ msg.Plain_JWT(msg));
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Plain and Dec are the same");
		else {
			System.out.println("They are not");	
		}
		
		System.out.println("PlainJWT "+ msg.Plain_JWT(msg).toString());
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Bingo 1");
		
		//The same thing has to be adopted for sent messages between participants.
		//There is probably no need for that, since we're using different methods to encrypt clients' exchanged messages and audit recs.
		String forAudit=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), auditPair.getPublic()));
		String VerifyAudit=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(DecJWT), auditPair.getPublic()));
		if (forAudit.equals(VerifyAudit))System.out.println("Bingo v");
    }
    
   //This has to be implemented in order to use keys from files, rather than from key store. THis is because we can't have the audit server's or the intended recipient's private key.
    //We would need to modify Enc_JWT and methods
   //It is OK for a proof of concept though.
/*public static void SendingandVerifyingMessagesandAuditRecsWithKeyFiles(Path privateKeyReceiver, Path publicKeyReceiver, Path privateKeyServer, Path publicKeyServer) throws Exception { //We are calling JWT methods using he JWTMsg object.
    	// 
    	JWTMsg msg=new JWTMsg("Data", "Issuer", "Recipient", "Label", new String[] {"Prev1", "Prev2"}, new String[] {"ParaPrev1", "ParaPrev2"});
    	//KeyPair receiverPair =msg.getKeyPairFromFile("client3", "clientpw", clientpassphrase, "clientprivate");
		//KeyPair auditPair =msg.getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate");
		
    	
    	
    	PublicKey ReceiverpublicKey = 
    		    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyReceiver)));
    	PrivateKey ReceiverPrivateKey = 
    		    KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(Files.readAllBytes(privateKeyReceiver)));
    	PublicKey AuditpublicKey = 
    		    KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Files.readAllBytes(publicKeyServer)));
    	PrivateKey AuditPrivateKey = 
    		    KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(Files.readAllBytes(privateKeyServer)));
		
    	
    	
    	
		String JWTEncMsg= msg.Enc_JWT(msg,(RSAPublicKey) ReceiverpublicKey);
		String DecJWT= msg.Dec_JWT(JWTEncMsg, (RSAPrivateKey) ReceiverPrivateKey);
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Plain and Dec are the same");
		else {
			System.out.println("They are not");	
		}
		
		System.out.println("PlainJWT "+ msg.Plain_JWT(msg).toString());
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Bingo 1");
		
		//The same thing has to be adopted for sent messages between participants.
		//There is probably no need for that, since we're using different methods to encrypt clients' exchanged messages and audit recs.
		String forAudit=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), AuditpublicKey));
		String VerifyAudit=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(DecJWT), AuditpublicKey));
		if (forAudit.equals(VerifyAudit))System.out.println("Bingo v");
    }*/
    
    
    
    private static void sendMessageToParticipant(String RecipientURL, JWTMsg msg, String SenderPrivateKey, String senderAddress, String receiverKeyPair, String auditKeyPair) throws Exception {//Maybe rename it. //This method sends a message from one participant to another following our protocol
    	//Renamed from sendTransaction
    	/* Work on SendingandVerifyingMessagesandAuditRecsWithKeyFiles to deal with the keys.
    	 * Steps: Publish audit record of the message, encrypted with the workflow public key, to the audit server
    	 * Send message, encrytped with the recipient's public key, to the intended recipient.
    	 * */
    	KeyPair receiverPair =msg.getKeyPairFromFile(receiverKeyPair, "clientpw", clientpassphrase, "clientprivate");
		KeyPair auditPair =msg.getKeyPairFromFile(auditKeyPair, "serverpw", serverpassphrase, "serverprivate");
		
		String JWTEncMsg= msg.ArraytoStringCleanCut(msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), receiverPair.getPublic()));//msg.Enc_JWT(msg,(RSAPublicKey)receiverPair.getPublic());
		//System.out.println("Encrypted String Sent to Next participant " +JWTEncMsg);
		//My guess is that when encrypting a string with a public key, its size changes.<=========
		String[] EncryptedArray=msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), receiverPair.getPublic());
		/////System.out.println("Printing Array: "+ EncryptedArray.toString());
		
		String JWTEncAudit= msg.ArraytoStringCleanCut(msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), auditPair.getPublic()));//msg.Enc_JWT(msg,(RSAPublicKey)auditPair.getPublic());
		
		////System.out.println("PrePublish. ");
		publishAuditRecord(SenderPrivateKey, JWTEncAudit, senderAddress);
		////System.out.println("Publishing Passed. ");
		//sendHTTPMessage(RecipientURL,JWTEncMsg); It works if I type the string though.
		/*We have a problem here. For some readon, I cannot send JWTEncMsg.
		 * */
		////System.out.println("What I am trying to send: "+JWTEncMsg);
		sendHTTPMessage(RecipientURL,JWTEncMsg);
		//sendHTTPMessage(RecipientURL,"cZbLrbvnftn4pGNPU0PMpZTS0kQPTywNMDr3qY3GT78LEtjN4xP+kZcqVO3QtjDoDQiVT11KM7fwTvPDratEUyfHhY3JjskAgIpqaufmNBpSBNiJawcw9F+OZxpUwltUZQHfRrp0H9ZCnrMqeaCLegFFWAK8WKa4BH2UluBSbtviEgHqS1WO1P+Lf75MjdoKsYDDhVLjx6VGJHLI0gcWxBZvBkHBhy7FfwHKMdW0gtirNmuyQhBr8luWxYEp1M/wYNENhUKrYFuaJ5F2NLKblzL0g/K0SZNUcq2J9mqXNf6mWPepgXvNjT608nHMTNhNgYK7hQX2SI0B++ZzXD7XKw==");//Send msg from here, participant will on the other end verifies the record.
    }

    private static void sendHTTPMessage(String URL, String message) throws Exception {//Added throuws Exception
//This is to send messages from one participant to another. An audit record has to go in parallel with this action. 
    	//Messages have to be encrypted with the recipient's public key, and audit records with the workflow's public key.
        RestTemplate restTemplate = new RestTemplate();
        
        restTemplate.postForLocation(URL, message);
        
       // byte[] signature = SignatureUtils.sign(text.getBytes(), Files.readAllBytes(privateKey));
        //Here, the sender signs the text prior to sending it.
        //Transaction transaction = new Transaction(text, senderHash, signature, LocalHash);
       // restTemplate.post(node.toString() + "/interface?publish=true", message);
       // System.out.println("Hash of new transaction: " + Base64.encodeBase64String(transaction.getHash()));
    }
  



    public static void publishAddress(String PubKey, String name) throws MalformedURLException, IOException {
	 publishAddress(new URL("http://localhost:8080"), Paths.get(PubKey), name);
}

    
    
    private static void publishTransaction(URL node, Path privateKey, String text, byte[] senderHash, String LocalHash) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
       // System.out.println("What we are publishing "+text);
        byte[] signature = SignatureUtils.sign(text.getBytes(), Files.readAllBytes(privateKey));
        //Here, the sender signs the text prior to sending it.
        Transaction transaction = new Transaction(text, senderHash, signature, LocalHash);
        restTemplate.put(node.toString() + "/transaction?publish=true", transaction);
      //  System.out.println("Hash of new transaction: " + Base64.encodeBase64String(transaction.getHash()));
    }
    
    public static void publishAuditRecord(String publisheprivatekey, String auditRecord, String sender) throws MalformedURLException, Exception{// Uses publishTransaction()
	//First we need to update our audit records by pulling from the audit server, and performing the audit server verification simultaneously
	AuditServerVerificartion();
	//we first add the record to the local storage, and to the list of out audit records
	addPostedAuditRec(auditRecord);addStoredAuditRec(auditRecord);
	//THen we calculate the hash of the stored audit recs, and we post to the server.
	publishTransaction(new URL("http://localhost:8080"), Paths.get(publisheprivatekey), auditRecord, Base64.decodeBase64(sender), Arrays.toString(calculateLocalHash()));//change the type of calculateLocalHash();
//Right after publishTransaction, mostRecentAuditRecord and mostRecentReportedLocalHash have to be updated. This is why we are pulling.
pullAudits();// Verify that tthe audit record shows on the audit server/

    }
    
    

    private static void publishAddress(URL node, Path publicKey, String name) throws IOException { //This is for the client to register with the audit node (audit server).
    RestTemplate restTemplate = new RestTemplate();
    Address address = new Address(name, Files.readAllBytes(publicKey));
    restTemplate.put(node.toString() + "/address?publish=true", address);
    addresstoPublish= Base64.encodeBase64String(address.getHash());
    System.out.println("Hash of new address: " + Base64.encodeBase64String(address.getHash()));
}


   

    private static void generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, IOException { //This is to generate key pairs. It is used by the key manager. Not needed if we already have ones.
    	
        KeyPair keyPair = SignatureUtils.generateKeyPair();
        Files.write(Paths.get("key3.priv"), keyPair.getPrivate().getEncoded());
        Files.write(Paths.get("key3.pub"), keyPair.getPublic().getEncoded());
    }


    
    public static void SetRecentAuditRecord(String mostRecentAuditRecordtemp, Long mostRecentReportingTimetemp, String mostRecentReportedLocalHashtemp) {
    	//THis method is to set the most recent audit records on the audit server, pulled by this client.
    	mostRecentAuditRecord=mostRecentAuditRecordtemp;
    	mostRecentReportingTime=mostRecentReportingTimetemp;
    	mostRecentReportedLocalHash=mostRecentReportedLocalHashtemp;
    }
    
    public static void pullAudits() throws Exception { //Filling the Hashmap pulledAuditRecs. It also locates the most recently published audit record, and assigns it to static variables using SetRecentAuditRecord(,,) 
    	//Adds audit records to a hashmap.
    	pulledAuditRecs.clear();
    	mostRecentReportingTime=(long) 0;
    	
        String url = "http://localhost:8080/transaction";
        URL obj = new URL(url);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        // optional default is GET
        con.setRequestMethod("GET");
        //add request header
        con.setRequestProperty("User-Agent", "Mozilla/5.0");
        int responseCode = con.getResponseCode();
       // System.out.println("\nSending 'GET' request to URL : " + url);
        //System.out.println("Response Code : " + responseCode);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(con.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();
        while ((inputLine = in.readLine()) != null) {
        	response.append(inputLine);
        }
        in.close();
        //print in String
        String ResponseStr=response.toString();
       // System.out.println(ResponseStr);
        //Now, I need to parse the response, if it is not empty
        
        if(!ResponseStr.equals("[]")) {
       String[] parsedResponse=ResponseStr.split("},");

       for (int i =0; i < parsedResponse.length; i++) {
       	//System.out.println(parsedResponse[i]);
       	if(i==0) { 
       		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(1, parsedResponse[i].length())+"}");
       		//System.out.println("Getcipher- "+myResponse.getString("cipher"));
       		pulledAuditRecs.add(myResponse.getString("cipher"));pulledAuditRecsReportingTime.add(myResponse.getLong("timestamp"));
       		if(myResponse.getLong("timestamp")>mostRecentReportingTime) {
       			SetRecentAuditRecord(myResponse.getString("cipher"), myResponse.getLong("timestamp"), myResponse.getString("localDigest"));
       		}
       	}
       	else if(i==parsedResponse.length-1) {
       		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(0, parsedResponse[i].length()-1));
       		//System.out.println("Getcipher- "+myResponse.getString("cipher"));
       		pulledAuditRecs.add(myResponse.getString("cipher"));pulledAuditRecsReportingTime.add(myResponse.getLong("timestamp"));
       		if(myResponse.getLong("timestamp")>mostRecentReportingTime) {
       			SetRecentAuditRecord(myResponse.getString("cipher"), myResponse.getLong("timestamp"), myResponse.getString("localDigest"));
       		}
       	}
       	
       	else {
       		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(0, parsedResponse[i].length())+"}");
       		//System.out.println("Getcipher- "+myResponse.getString("cipher"));
       		pulledAuditRecs.add(myResponse.getString("cipher"));pulledAuditRecsReportingTime.add(myResponse.getLong("timestamp"));
       		if(myResponse.getLong("timestamp")>mostRecentReportingTime) {
       			SetRecentAuditRecord(myResponse.getString("cipher"), myResponse.getLong("timestamp"), myResponse.getString("localDigest"));
       		}
       	}
       	
       }
    } else System.out.println("There is nothing to Pull.");
     //  System.out.println("List Size: "+audit_recs.size());}
}

  
    public static List<String> hashmapToArrayList(Set<String> Hashset) { //I think this is what is shuffling the elements
    	String[] temp=	 (String[]) Hashset.toArray(new String[Hashset.size()]);
    	List<String> arrayList = new ArrayList<String>(Arrays.asList(temp));
		return arrayList;
    	
    }
    
    public static String[] ArraylistToArray(List<String> list) { //I think this is what is shuffling the elements
    	String[] temp = new String[list.size()];
    	temp = list.toArray(temp);

    	return temp;
    	
    }
    

    public static String ArrayListtoString(List<String> strList) {
	String combine="";
	for(int i=0; i<strList.size(); i++) {
		combine+=strList.get(i);
	}
	return combine;
}
    
    
    private static byte[] calculateLocalHash() {
        String hashableData = ArrayListtoString(getStoredAuditRecs());
        //System.out.println("hashableData "+ hashableData);
        return DigestUtils.sha256(hashableData);
    }
    
    // We can test this by posting recs manually.
    public static boolean AuditServerVerificartion() throws Exception {pullAudits();//This updates a hashmap, which means that its size remains the same if you run it multiple times.
//if audit server is clear, and no messages have been posted by client, return true.
    if(pulledAuditRecs.isEmpty()&&getStoredAuditRecs().isEmpty()&&getPostedAuditRecs().isEmpty()) {
	System.out.println("Nobody has posted yet.");
	return true;//did not work.
    	}
    	
for (int i = 0; i < getPostedAuditRecs().size(); i++) {
			if(!pulledAuditRecs.contains(getPostedAuditRecs().get(i))) {System.out.println("Audit Server Verification Failure. "+getPostedAuditRecs().get(i)+"Does not exist on the server");
				return false;
			}
		}
    	for (int i = 0; i < getStoredAuditRecs().size(); i++) {
			if(!pulledAuditRecs.contains(getStoredAuditRecs().get(i))) {System.out.println("Audit Server Verification Failure. "+getStoredAuditRecs().get(i)+"Does not exist on the server");
				return false;
			}
		}
    	
    	setStoredAuditRecs(pulledAuditRecs);//Local hash seems to be messed up after this.
    	// The resulting hash value is nnot correct
    	//This does not have the same order as the arraylist
    	//Maybe change the data structure in transactions to arraylist?  
    	//The pulled data from the server has a different order from what is stored locally in an arraylist.
    	
    	//Here, we need to calculate the hash of setStoredAuditRecs and compare it with mostRecentReportedLocalHash.
    	if(Arrays.toString(calculateLocalHash()).equals(mostRecentReportedLocalHash)) return true;
    	else {
    		System.out.println("Audit server Malicious behaviour. Your Local hash does not coincide with another participant's.");
    		return false;
    	}
    }

    public static boolean AuditRecordverification(String receivedMsg) throws Exception {// To Implement.
    	pullAudits();
    	JWTMsg m=new JWTMsg();
    	PublicKey auditPublic =m.getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate").getPublic();
    	String VerifyAudit=m.ArraytoString(m.encrypt_long(m.Split_to_List(receivedMsg), auditPublic));
		
    	//To implement every detail of this, we need to parse the message to obtain the lable. This has to be done in case it is used in production.
			if(!pulledAuditRecs.contains(VerifyAudit)) {System.out.println("Audit Record Verification Failure. "+"Audit Record of the message that you received was not reported.");
			return false;
			}
			else{
			//If this record has been reported, then:
				JWTMsg ReceivedJWTMsg=new JWTMsg(receivedMsg);
				if(ReceivedJWTMsg.getLabel().equalsIgnoreCase("ini")) {
					if(pulledAuditRecs.size()==1) return true;
				}
				if(ReceivedJWTMsg.getLabel().equalsIgnoreCase("ini,parallel")){
					for(int i=0; i<pulledAuditRecsReportingTime.size()-1; i++) {
						if(pulledAuditRecsReportingTime.get(i)-pulledAuditRecsReportingTime.get(i+1)>epsilon) return false;
					}return true;
				}
				if(ReceivedJWTMsg.getPrev().equals(null)&&ReceivedJWTMsg.getParaPrev().equals(null))return false;
				else {
					if(!ReceivedJWTMsg.getPrev().equals(null)) {
						for(int i=0; i<ReceivedJWTMsg.getPrev().length;i++) {
							if(!pulledAuditRecs.contains(ReceivedJWTMsg.getPrev()[i])) {
								System.out.println("Previous record not valid in the message");
								return false;
							}
						}
					}
					if(!ReceivedJWTMsg.getParaPrev().equals(null)) {
						for(int i=0; i<ReceivedJWTMsg.getParaPrev().length; i++) {
							if(!pulledAuditRecs.contains(ReceivedJWTMsg.getParaPrev()[i])) {
								System.out.println("Previous record not valid in the message");
								return false;
							}
						}
					}
				}
			
			}
			
			
			return true;
    }

    public static boolean EncryptedAuditRecordverification(String EncryptedReceivedMsg, String ClientPair) throws Exception {// To Implement.
    	pullAudits();
    	JWTMsg m=new JWTMsg();
    	PublicKey auditPublic =m.getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate").getPublic();
    	KeyPair receiverPair =m.getKeyPairFromFile(ClientPair, "clientpw", clientpassphrase, "clientprivate");
		//String JWTEncMsg= msg.Enc_JWT(msg,(RSAPublicKey)receiverPair.getPublic());
    	//System.out.println("0");
    	//==========> Maybe try cleaning the encrypted message///////////// Does not harm but not useful
    	/*System.out.println("This is how the receiver got the message: "+EncryptedReceivedMsg);
    	String CleanedRecievedMessage=m.CleanReceivedPrevForVerification(EncryptedReceivedMsg);
    	String[] receivedMsgArray=m.StringCleanCuttoArray(CleanedRecievedMessage);*/
    	//
    	String[] receivedMsgArray=m.StringCleanCuttoArray(EncryptedReceivedMsg);///////////////////
    	
    	//System.out.println("1");
    //	String receivedMsgArrayDecrypt[]= m.decrypt_long(receivedMsgArray, (RSAPrivateKey)receiverPair.getPrivate());
    	//System.out.println("2- Problem seems to be here.");
    	String receivedMsg=m.ArraytoString(m.decrypt_long(receivedMsgArray, (RSAPrivateKey)receiverPair.getPrivate()));
    	//String receivedMsg= m.Dec_JWT(EncryptedReceivedMsg, (RSAPrivateKey)receiverPair.getPrivate());
		//System.out.println("Received Msg After Decrypt:" +receivedMsg+ "END");
    	String VerifyAudit=m.ArraytoStringCleanCut(m.encrypt_long(m.Split_to_List(receivedMsg), auditPublic));
		
    	//To implement every detail of this, we need to parse the message to obtain the lable. This has to be done in case it is used in production.
			if(!pulledAuditRecs.contains(VerifyAudit)) {System.out.println("Audit Record Verification Failure. "+"Audit Record of the message that you received was not reported.");
			return false;
			}
			else{ AuditRecsforReceivedMessages.add(VerifyAudit);// adding the equivalent audit record to the storage of the participant for future use
			//If this record has been reported, then:
				JWTMsg ReceivedJWTMsg=new JWTMsg(receivedMsg);
				if(ReceivedJWTMsg.getLabel().equalsIgnoreCase("ini")) {
					if(pulledAuditRecs.size()==1) {System.out.println("EncryptedAuditRecordverification Passed");
						return true;}
				}
				if(ReceivedJWTMsg.getLabel().equalsIgnoreCase("ini,parallel")){
					for(int i=0; i<pulledAuditRecsReportingTime.size()-1; i++) {
						if(pulledAuditRecsReportingTime.get(i)-pulledAuditRecsReportingTime.get(i+1)>epsilon) return false;
					} return true;
				}
				if(ReceivedJWTMsg.getPrev().equals(null)&&ReceivedJWTMsg.getParaPrev().equals(null))return false;
				else {
					if(ReceivedJWTMsg.getPrev().length!=0) {//if(!ReceivedJWTMsg.getPrev().equals(null)) {
						for(int i=0; i<ReceivedJWTMsg.getPrev().length;i++) {
							
							//System.out.println("Before Cleaning "+ReceivedJWTMsg.getPrev()[i]);
							//System.out.println("After Cleaning "+m.CleanReceivedPrevForVerification(ReceivedJWTMsg.getPrev()[i]));
							if(!pulledAuditRecs.contains(m.CleanReceivedPrevForVerification(ReceivedJWTMsg.getPrev()[i]))) {//Here is where things are going wrong.
								System.out.println("Prev Previous record "+ReceivedJWTMsg.getPrev()[i]+ " is not valid in the message");
								return false;
							}
						}
					}
					if(ReceivedJWTMsg.getParaPrev().length!=0) {//if(!ReceivedJWTMsg.getParaPrev().equals(null)) {
						for(int i=0; i<ReceivedJWTMsg.getParaPrev().length; i++) {
							if(!pulledAuditRecs.contains(m.CleanReceivedPrevForVerification(ReceivedJWTMsg.getParaPrev()[i]))) {
								System.out.println("ParaPrev Previous record "+ ReceivedJWTMsg.getParaPrev()[i]+ " is not valid in the message");
								return false;
							}
						}
					}
				}
			
			}
			
			System.out.println("EncryptedAuditRecordverification Passed");
			return true;
    }


}


