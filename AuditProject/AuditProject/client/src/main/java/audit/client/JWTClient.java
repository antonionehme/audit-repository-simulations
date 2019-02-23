package audit.client;

import org.apache.commons.cli.*;
import org.apache.commons.codec.binary.Base64;
import org.springframework.web.client.RestTemplate;

import audit.client.JWTMsg;
import audit.common.SignatureUtils;
import audit.common.domain.Address;
import audit.common.domain.Transaction;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


/**
 * Simple class to help building REST calls for jBlockchain.
 * Just run it in command line for instructions on how to use it.
 *
 * Functions include:
 * - Generate Private/Public-Key
 * - Publish a new Address
 * - Publish a new Transaction
 */
public class JWTClient {
	private static KeyStore clientKeyStore;
	  static private final String clientpassphrase = "clientpw";
	  static private final String serverpassphrase = "serverpw";
	  
    public static void main(String args[]) throws Exception {
    	//Added to combine JWTMsg with JWT Client
    	JWTMsg msg=new JWTMsg("Data", "Issuer", "Recipient", "Label", new String[] {"Prev1", "Prev2"}, new String[] {"ParaPrev1", "ParaPrev2"});
    	KeyPair receiverPair =msg.getKeyPairFromFile("client2", "clientpw", clientpassphrase, "clientprivate");
		KeyPair auditPair =msg.getKeyPairFromFile("server", "serverpw", serverpassphrase, "serverprivate");
		
		
		
		String JWTEncMsg= msg.Enc_JWT(msg,(RSAPublicKey)receiverPair.getPublic());
		String DecJWT= msg.Dec_JWT(JWTEncMsg, (RSAPrivateKey)receiverPair.getPrivate());
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Plain and Dec are the same");
		else {
			System.out.println("They are not");	
		}
		
		System.out.println("PlainJWT "+ msg.Plain_JWT(msg).toString());
		if (msg.Plain_JWT(msg).equals(DecJWT))System.out.println("Bingo 1");
		
		String msgString=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(msg.Plain_JWT(msg)), auditPair.getPublic()));
		String forAudit=msg.ArraytoString(msg.encrypt_long(msg.Split_to_List(DecJWT), auditPair.getPublic()));
		if (msgString.equals(forAudit))System.out.println("Bingo v");
    	
		/////////////////////////////////
		
        CommandLineParser parser = new DefaultParser();
        Options options = getOptions();
        try {
            CommandLine line = parser.parse(options, args);
            executeCommand(line, forAudit);
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("BlockchainClient", options , true);
        }
        
        
    }
    

    private static void executeCommand(CommandLine line, String toPost) throws Exception {
        if (line.hasOption("keypair")) {
            generateKeyPair();
        } else if (line.hasOption("address")) {
            String node = line.getOptionValue("node");
            String name = line.getOptionValue("name");
            String publickey = line.getOptionValue("publickey");
            
            
            if (node == null || name == null || publickey == null) {
                throw new ParseException("node, name and publickey is required");
            }
            publishAddress(new URL(node), Paths.get(publickey), name);

        } else if (line.hasOption("transaction")) {//Maybe replace this with else go to another method or probably do nothing.
        	//We should jump to publishTransaction().
            String node = line.getOptionValue("node");
            String message = toPost;//line.getOptionValue("message");
            String sender = line.getOptionValue("sender");
            String privatekey = line.getOptionValue("privatekey");
            if (node == null || message == null || sender == null || privatekey == null) {
                throw new ParseException("node, message, sender and privatekey is required");
            }
            publishTransaction(new URL(node), Paths.get(privatekey), message, Base64.decodeBase64(sender), "This is the Local Hash");
        }
    }


    private static void executeCommand(CommandLine line) throws Exception {
        if (line.hasOption("keypair")) {
            generateKeyPair();
        } else if (line.hasOption("address")) {
            String node = line.getOptionValue("node");
            String name = line.getOptionValue("name");
            String publickey = line.getOptionValue("publickey");
            
            
            if (node == null || name == null || publickey == null) {
                throw new ParseException("node, name and publickey is required");
            }
            publishAddress(new URL(node), Paths.get(publickey), name);

        } else if (line.hasOption("transaction")) {
            String node = line.getOptionValue("node");
            String message = line.getOptionValue("message");
            String sender = line.getOptionValue("sender");
            String privatekey = line.getOptionValue("privatekey");
            if (node == null || message == null || sender == null || privatekey == null) {
                throw new ParseException("node, message, sender and privatekey is required");
            }
            publishTransaction(new URL(node), Paths.get(privatekey), message, Base64.decodeBase64(sender), "This is the Local Hash");
        }
    }

    private static Options getOptions() {
        OptionGroup actions = new OptionGroup();
        actions.addOption(new Option("k", "keypair", false, "generate private/public key pair"));
        actions.addOption(new Option("a", "address", false, "publish new address"));
        actions.addOption(new Option("t", "transaction", false, "publish new transaction"));
        actions.setRequired(true);

        Options options = new Options();
        options.addOptionGroup(actions);
        options.addOption(Option.builder("o")
                .longOpt("node")
                .hasArg()
                .argName("Node URL")
                .desc("needed for address and transaction publishing")
                .build());
        options.addOption(Option.builder("n")
                .longOpt("name")
                .hasArg()
                .argName("name for new address")
                .desc("needed for address publishing")
                .build());
        options.addOption(Option.builder("p")
                .longOpt("publickey")
                .hasArg()
                .argName("path to key file")
                .desc("needed for address publishing")
                .build());
        options.addOption(Option.builder("v")
                .longOpt("privatekey")
                .hasArg()
                .argName("path to key file")
                .desc("needed for transaction publishing")
                .build());
        options.addOption(Option.builder("m")
                .longOpt("message")
                .hasArg()
                .argName("message to post")
                .desc("needed for transaction publishing")
                .build());
        options.addOption(Option.builder("s")
                .longOpt("sender")
                .hasArg()
                .argName("address hash (Base64)")
                .desc("needed for transaction publishing")
                .build());

        return options;
    }

    private static void generateKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
        KeyPair keyPair = SignatureUtils.generateKeyPair();
        Files.write(Paths.get("key2048.priv"), keyPair.getPrivate().getEncoded());
        Files.write(Paths.get("key2048.pub"), keyPair.getPublic().getEncoded());
    }

    private static void publishAddress(URL node, Path publicKey, String name) throws IOException {
        RestTemplate restTemplate = new RestTemplate();
        Address address = new Address(name, Files.readAllBytes(publicKey));
        restTemplate.put(node.toString() + "/address?publish=true", address);
        System.out.println("Hash of new address: " + Base64.encodeBase64String(address.getHash()));
    }

    private static void publishTransaction(URL node, Path privateKey, String text, byte[] senderHash, String LocalHash) throws Exception {
        RestTemplate restTemplate = new RestTemplate();
        
        byte[] signature = SignatureUtils.sign(text.getBytes(), Files.readAllBytes(privateKey));
        //Here, the sender signs the text prior to sending it.
        Transaction transaction = new Transaction(text, senderHash, signature, LocalHash);
        restTemplate.put(node.toString() + "/transaction?publish=true", transaction);
        System.out.println("Hash of new transaction: " + Base64.encodeBase64String(transaction.getHash()));
    }
}
