package audit.client;

import java.util.Collections;
import java.util.Map;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.google.api.client.util.Maps;


@SpringBootApplication
public class Client1 {

	public static void main(String[] args) {
		
		SpringApplication app = new SpringApplication(Client1.class);
		Map<String, Object> pro = Maps.newHashMap();
        pro.put("server.port", "8091");

        app.setDefaultProperties(pro);
        app.run(args);
        
	//	SpringApplication.run(Client1.class, args);
	}
}
