package audit.server;

import java.util.Scanner;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import audit.server.rest.TransactionController;
import audit.server.service.AddressService;
import audit.server.service.TransactionService;


@SpringBootApplication
public class AuditNode extends TransactionService {

	public AuditNode(AddressService addressService) {//Had to add this.
		super(addressService);
		// TODO Auto-generated constructor stub
	}

	public static void main(String[] args) throws Exception {
		SpringApplication.run(AuditNode.class, args);
		SimulateMalitiousBehaviour();
	}
	
	 public static void SimulateMalitiousBehaviour() throws Exception { Scanner scan=new Scanner(System.in);
	 System.out.println("1 to Delete a rec, 2 to delete All.");
 	String option=scan.nextLine();
 	while(option!="X") {
     switch(option) {
     case "1" :{ System.out.println("Deleting a record from the Audit Server");
     removefirst();
     System.out.println("1 to Delete a rec, 2 to delete All.");
     	option=scan.nextLine();
     	}
        break;
        
     case "2" :{ System.out.println("Deleted All Records from the Audit Server");
     removeAll();
     System.out.println("1 to Delete a rec, 2 to delete All.");
     	option=scan.nextLine();}
        break;
     
     default :{
        System.out.println("Invalid Option");
        option=scan.nextLine();}
  }
     }
  
}
}
