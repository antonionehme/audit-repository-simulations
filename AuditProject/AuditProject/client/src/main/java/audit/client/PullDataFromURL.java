package audit.client;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.json.JSONObject;
public class PullDataFromURL {
	static List<String> audit_recs = new ArrayList<>();
	public static void main(String[] args) {
		
     try {
         call_me();
        } catch (Exception e) {
         e.printStackTrace();
       }
     }
	   
public static void call_me() throws Exception {
	
	
     String url = "http://localhost:8080/transaction";
     URL obj = new URL(url);
     HttpURLConnection con = (HttpURLConnection) obj.openConnection();
     // optional default is GET
     con.setRequestMethod("GET");
     //add request header
     con.setRequestProperty("User-Agent", "Mozilla/5.0");
     int responseCode = con.getResponseCode();
     System.out.println("\nSending 'GET' request to URL : " + url);
     System.out.println("Response Code : " + responseCode);
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
     System.out.println(ResponseStr);
     //Now, I need to parse the response
    String[] parsedResponse=ResponseStr.split("},");
    /*
First=[{"hash":"u2eO+3eFij77S1tQgX3Ha7kF1DLU+SehjgdsLbObYqg=","text":"Hello World","senderHash":"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=","signature":"MCwCFDBDAqq6hWHbqhb4vlzSnlPHOeR5AhRllxOlqDXPGMqpGOTBmP8zhAeH/A==","timestamp":1544011758537,"signableData":"SGVsbG8gV29ybGQ="
[1]={"hash":"zNXc1VfOUY/prfqtfCl3ZOxJeFUITxMRDZtfZHU3o5A=","text":"HelloAgain","senderHash":"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=","signature":"MCsCFDObx6o3NJvj3c2ZNm8hnQHDETszAhMkB0pvNhQgQezmneBNh6oAIx06","timestamp":1544015014760,"signableData":"SGVsbG9BZ2Fpbg=="
[2]={"hash":"R3iMWTeVDvPtvDbyAjE25RR+JLLklzcf806kXyzXwWo=","text":"Hello---World","senderHash":"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=","signature":"MC0CFHOejY2WczPVAwUMhZv69J2ImUqoAhUAldPjiaTB7BGsvgh0164n091NX0M=","timestamp":1544013306601,"signableData":"SGVsbG8tLS1Xb3JsZA=="
Last={"hash":"yacmWZU73IffOK+6Oy7qsI1ZNELE7WPrOrCRNLGOkSo=","text":"OmeMoreTime","senderHash":"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=","signature":"MCwCFGckkzEiDoS2b/v9/CgSlTS7wkBKAhQYL2sYi19uSqR/x6HDo3GJyiAJlA==","timestamp":1544015052471,"signableData":"T21lTW9yZVRpbWU="}]
     */
    /*
    System.out.println("Begin");
    System.out.println(parsedResponse[0]);
    System.out.println(parsedResponse[1]);
    System.out.println(parsedResponse[2]);
    System.out.println(parsedResponse[3]);
    System.out.println("End");*/

    for (int i =0; i < parsedResponse.length; i++) {
    	//System.out.println(parsedResponse[i]);
    	if(i==0) {
    		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(1, parsedResponse[i].length())+"}");
    		System.out.println("Getcipher- "+myResponse.getString("cipher"));
    		audit_recs.add(myResponse.getString("cipher"));
    	}
    	else if(i==parsedResponse.length-1) {
    		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(0, parsedResponse[i].length()-1));
    		System.out.println("Getcipher- "+myResponse.getString("cipher"));
    		audit_recs.add(myResponse.getString("cipher"));
    	}
    	
    	else {
    		JSONObject myResponse =new JSONObject(parsedResponse[i].substring(0, parsedResponse[i].length())+"}");
    		System.out.println("Getcipher- "+myResponse.getString("cipher"));
    		audit_recs.add(myResponse.getString("cipher"));
    	}
    	
    }
    System.out.println("List Size: "+audit_recs.size());
   // String[] array = {"1","2"};
   // ArrayList<String> audit_recs_l = new ArrayList<String>(Arrays.asList(array));
    
    
     
     
     
     //Read JSON response and print
     //JSONObject myResponse =new JSONObject(parsedResponse[0].substring(1, parsedResponse[0].length())+"}");
    		 //new JSONObject("{\"hash\":\"u2eO+3eFij77S1tQgX3Ha7kF1DLU+SehjgdsLbObYqg=\",\"text\":\"Hello World\",\"senderHash\":\"HEWtNSfUAMKEitKc5MBThupdOTj98oV/VaLG9LbR5Ms=\",\"signature\":\"MCwCFDBDAqq6hWHbqhb4vlzSnlPHOeR5AhRllxOlqDXPGMqpGOTBmP8zhAeH/A==\",\"timestamp\":1544011758537,\"signableData\":\"SGVsbG8gV29ybGQ=\"}");
     //System.out.println("result after Reading JSON Response");
// System.out.println("GetText- "+myResponse.getString("text"));
    /* System.out.println("statusMessage- "+myResponse.getString("statusMessage"));
     System.out.println("ipAddress- "+myResponse.getString("ipAddress"));
     System.out.println("countryCode- "+myResponse.getString("countryCode"));
     System.out.println("countryName- "+myResponse.getString("countryName"));
     System.out.println("regionName- "+myResponse.getString("regionName"));
     System.out.println("cityName- "+myResponse.getString("cityName"));
     System.out.println("zipCode- "+myResponse.getString("zipCode"));
     System.out.println("latitude- "+myResponse.getString("latitude"));
     System.out.println("longitude- "+myResponse.getString("longitude"));
     System.out.println("timeZone- "+myResponse.getString("timeZone"));  */
   }
}