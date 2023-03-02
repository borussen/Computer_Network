import java.util.Scanner;

class Q1493_수의새로운연산 {
	public static void main(String args[]) throws Exception {
		Scanner sc = new Scanner(System.in);
		int T = sc.nextInt();

		for (int tc = 1; tc <= T; tc++) {
			int p = sc.nextInt();
			int q = sc.nextInt();
			
			int num1 = 0;
			int num2 = 0;
			int sum1 = 0;
			int sum2 = 0;
			
			while(true) {
				sum1 += ++num1;
				if(p <= sum1) break;
			}
			while(true) {
				sum2 += ++num2;
				if(q <= sum2) break;
			}
			
			int px = num1 - (sum1 - p);
			int py = 1 + (sum1 - p);
			int qx = num2 - (sum2 - q);
			int qy = 1 + (sum2 - q);
			
			int x = px + qx;
			int y = py + qy;
			
			int sum3 = 0;
			for (int n = 1; n < x + y; n++)
				sum3 += n;
			
			int result = sum3 - (y - 1);
			
			System.out.println("#" + tc + " " + result);
		}
	}
}