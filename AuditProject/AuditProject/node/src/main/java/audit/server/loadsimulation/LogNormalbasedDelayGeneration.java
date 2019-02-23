package audit.server.loadsimulation;
import audit.server.loadsimulation.Math;
import audit.server.loadsimulation.LogNormalDistribution;
import java.util.Random;
import java.io.FileWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
//import java.lang.Math;

public class LogNormalbasedDelayGeneration {
   /* public static double mu;
    public static double sigma;*/
    
    public static double LogNormalGenerated(double mu, double sigma) { //Long L=(long) -200;
    	Random r = new Random();
    	double random=r.nextDouble();
    	double random_2=2*random;
	double logdelay=mu+ (random_2*sigma);
	double Ret=Math.exp(logdelay);
	return Ret;
    }
    
    public static void simulate_delay(double [] experiments_data, int number_of_generated_points, double constant, double tweaked_mu, double tweaked_sigma, String output) throws IOException {
    	
    	String file = output;
    	FileWriter file_writer = new FileWriter(file);
    	String FILE_HEADER = "Constrant "+constant+ " Mu "+ tweaked_mu+ " sigma "+ tweaked_sigma+", ResponseTime with Delay of C*e^(mu+sigma) of the simulation"+"\n";
    	file_writer.append(FILE_HEADER.toString());
    	
    	file_writer.flush(); file_writer.flush();//this is to create the emtpy file
    	
    			LogNormalDistribution lnd= new LogNormalDistribution(experiments_data);
    			
    			FileWriter fileWriter = new FileWriter(file,true);//write on top of the existent file
    			
    	for(int i=0;i<number_of_generated_points;i++) {
    		double runtime_with_delay=LogNormalGenerated(lnd.getMu(),lnd.getSigma())+constant*LogNormalGenerated(tweaked_mu,tweaked_sigma);
    		fileWriter.append("iteration "+i+", "+runtime_with_delay+"\n");
    		
    	}
    	fileWriter.flush();
        fileWriter.close();
    	
    	
    }
    
public static void main(String[]args) throws IOException {
	
	double [] experiments_data = new double [] {618, 624, 659, 657, 19, 28, 50, 78, 14, 24, 37, 45, 14, 20, 27, 47, 14, 20, 34, 49, 12, 17, 30, 53, 11, 20, 29, 38, 14, 19, 29, 37, 14, 17, 29, 33, 12, 22, 32, 39, 11, 19, 29, 36, 12, 17, 31, 35, 13, 17, 25, 41, 11, 18, 27, 35, 11, 16, 27, 37, 10, 17, 28, 37, 10, 16, 30, 34, 11, 21, 29, 39, 11, 21, 28, 38, 13, 18, 30, 34, 13, 17, 30, 34, 11, 16, 34, 48, 8, 13, 24, 38, 9, 14, 23, 38, 10, 15, 26, 33, 9, 14, 25, 31, 9, 14, 22, 35, 10, 17, 20, 33, 9, 13, 28, 32, 8, 13, 23, 34, 10, 12, 22, 36, 9, 15, 24, 31, 10, 13, 29, 32, 9, 13, 21, 33, 8, 13, 23, 30, 7, 13, 20, 29, 8, 12, 22, 31, 9, 13, 20, 31, 8, 20, 23, 41, 9, 14, 20, 30, 8, 13, 24, 32, 7, 12, 23, 29, 9, 13, 20, 35, 8, 12, 21, 30, 8, 12, 20, 30, 8, 14, 26, 30, 7, 14, 21, 30, 9, 13, 22, 29, 9, 12, 25, 32, 9, 13, 21, 30, 545, 498, 529, 567, 17, 21, 38, 64, 11, 17, 26, 43, 11, 16, 25, 41, 11, 17, 30, 33, 10, 18, 28, 43, 14, 15, 27, 39, 10, 18, 28, 39, 10, 15, 26, 33, 10, 14, 23, 37, 10, 14, 24, 39, 10, 14, 22, 34, 14, 14, 27, 35, 9, 15, 25, 37, 9, 14, 22, 33, 10, 14, 24, 34, 10, 14, 22, 35, 10, 15, 25, 34, 11, 14, 23, 42, 8, 16, 25, 34, 9, 15, 24, 32, 10, 14, 28, 36, 8, 14, 22, 63, 9, 13, 24, 43, 9, 13, 22, 32, 9, 13, 21, 35, 8, 12, 20, 30, 10, 13, 22, 30, 9, 19, 26, 31, 8, 14, 21, 33, 9, 14, 20, 33, 564, 606, 612, 759, 17, 23, 46, 61, 12, 16, 31, 49, 19, 17, 29, 40, 13, 18, 29, 40, 10, 16, 25, 43, 14, 16, 28, 38, 10, 14, 24, 34, 11, 14, 27, 33, 11, 20, 26, 39, 10, 13, 23, 41, 10, 16, 26, 42, 10, 15, 25, 38, 9, 18, 31, 35, 9, 18, 22, 44, 10, 19, 30, 39, 12, 14, 28, 32, 8, 19, 31, 37, 11, 14, 25, 35, 9, 17, 26, 40, 9, 15, 32, 36, 9, 16, 26, 32, 10, 14, 28, 46, 9, 12, 23, 37, 8, 13, 28, 30, 9, 14, 23, 32, 9, 12, 27, 36, 9, 14, 22, 33, 10, 17, 26, 32, 10, 13, 23, 35, 9, 12, 21, 31, 597, 646, 643, 627, 575, 569, 681, 610, 17, 25, 36, 59, 14, 23, 26, 49, 9, 16, 23, 47, 14, 16, 31, 30, 9, 20, 32, 34, 11, 14, 31, 29, 10, 14, 26, 43, 10, 16, 28, 34, 9, 19, 29, 34, 9, 14, 23, 35, 13, 13, 25, 33, 9, 15, 28, 88, 10, 16, 21, 33, 9, 14, 22, 30, 12, 13, 25, 31, 9, 14, 26, 32, 10, 13, 25, 31, 8, 15, 29, 40, 10, 22, 107, 44, 9, 15, 29, 34, 9, 15, 28, 42, 8, 13, 24, 49, 7, 18, 29, 46, 9, 13, 23, 36, 9, 14, 20, 38, 8, 13, 24, 34, 9, 13, 21, 28, 11, 15, 21, 35, 9, 13, 22, 28, 10, 14, 22, 31, 8, 16, 26, 37, 9, 13, 21, 33, 8, 12, 21, 41, 8, 14, 26, 31, 8, 14, 26, 32, 8, 13, 29, 28, 11, 15, 25, 32, 9, 11, 20, 29, 8, 11, 22, 29, 9, 13, 25, 31, 7, 12, 21, 37, 8, 14, 22, 30, 8, 13, 20, 30, 8, 14, 20, 29, 7, 13, 26, 29, 8, 11, 20, 29, 8, 13, 24, 28, 10, 12, 21, 31, 8, 12, 21, 28, 9, 13, 21, 29, 8, 11, 21, 35, 555, 486, 543, 499, 19, 26, 47, 61, 11, 17, 29, 41, 11, 16, 27, 44, 11, 18, 26, 42, 11, 16, 36, 40, 11, 16, 26, 36, 10, 20, 24, 36, 14, 15, 25, 33, 9, 18, 23, 43, 9, 16, 25, 34, 11, 15, 23, 31, 14, 16, 29, 67, 9, 13, 28, 32, 9, 14, 23, 34, 8, 14, 22, 36, 10, 14, 29, 33, 8, 14, 26, 34, 10, 12, 24, 38, 8, 19, 23, 31, 9, 15, 36, 32, 11, 20, 25, 38, 9, 20, 30, 46, 7, 15, 23, 33, 9, 14, 24, 33, 7, 13, 27, 42, 7, 18, 21, 36, 8, 15, 24, 32, 9, 15, 29, 33, 14, 14, 23, 37, 33, 9, 14, 20, 33};
	/*LogNormalDistribution lnd= new LogNormalDistribution(experiments_data);
	System.out.println(lnd.toString());
	System.out.println(LogNormalGenerated(3.0604,0.7907));*/
	double constant=1;
	int	 iterations=200;
	String file_name="1-05.csv";
	double mu=1;
	double sigma=0.5;
	simulate_delay(experiments_data, iterations, constant, mu, sigma, file_name);
	
	}
}
