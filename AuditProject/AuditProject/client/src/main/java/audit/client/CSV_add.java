package audit.client;
//import java.io.FileWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

public class CSV_add {
public static void main (String args[]) throws IOException {
	String file = "data.csv";
	String FILE_HEADER = "id,firstName"+"\n";
	FileWriter fileWriter = new FileWriter(file,true);
	long startTime = System.nanoTime();//currentTimeMillis()
	
	
    //Write the CSV file header
	fileWriter.append(FILE_HEADER.toString());
	fileWriter.append("1,Antonio"+"\n");
	
	long endTime = System.nanoTime();

	long duration = (endTime - startTime);
	System.out.println("it took"+ duration);
	
	fileWriter.flush();
    fileWriter.close();


}

}