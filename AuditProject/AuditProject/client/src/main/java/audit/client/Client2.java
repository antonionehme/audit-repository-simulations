package audit.client;

import java.util.Collections;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.google.api.client.util.Maps;


@SpringBootApplication
public class Client2 {

	public static void main(String[] args) {
		
		SpringApplication app = new SpringApplication(Client2.class);
		Map<String, Object> pro = Maps.newHashMap();
        pro.put("server.port", "8092");

        app.setDefaultProperties(pro);
        app.run(args);
        
	//	SpringApplication.run(Client1.class, args);
	}
}
