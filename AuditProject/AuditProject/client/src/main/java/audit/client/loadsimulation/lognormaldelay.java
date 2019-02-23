package audit.client.loadsimulation;
import java.util.Random;
//import java.lang.Math;

import audit.client.loadsimulation.Math;

public class lognormaldelay {
   /* public static double mu;
    public static double sigma;*/
    
    public static double delay(double mu, double sigma) { //Long L=(long) -200;
    	Random r = new Random();
	double logdelay=mu+ (r.nextDouble()*sigma);
	//System.out.println(logdelay);
	double Ret=Math.exp(logdelay)/2000000000;Ret=Ret/1000000;
	return Ret;
	
	//return (Math.exp(logdelay)/2000000000)/1000000;
    }
    
public static void main(String[]args) {
	
	System.out.println(delay(7.28,0.63));
	System.out.println(delay(1,1));
	/*double b=4;
	long a=(long)b/3;
	System.out.format("%,8f%n", a);
	System.out.println(a);*/
}
}
