import java.io.*;
import java.net.*;
import java.util.Random;
import java.math.BigInteger;
import java.util.Scanner;

/**
 * Client class creates client socket, connects to server, sends and receives messages to and from server.
 */
class Client { 

	public static void main(String arg[]) throws IOException {
		
		//boolean flags if user wants authentication or confidentiality
		boolean doAuth = false;
		boolean doSecure = false;
		
		//prompt user for bit size and y/n for auth or confid
		System.out.println("Please enter key size (512, 1024, 2048, 4096): ");
		Scanner userIn = new Scanner(System.in);
		int bits = Integer.parseInt(userIn.nextLine());
		
		System.out.println("Would you like to encrypt your messages? [y/n]: ");
		if (userIn.nextLine().equals("y"))
		{
			doSecure = true;
		}

		System.out.println("Would you like to authenticate your connection? [y/n]: ");
		if (userIn.nextLine().equals("y"))
		{
			doAuth = true;
		}
		
		//startTime and endTime calculates latency of makeKeys function
		long startTime = System.nanoTime();
		//makeKeys creates public and private keys, stores in keyStuff
		BigInteger[] keyStuff = makeKeys(bits);
		long endTime = System.nanoTime();
		//output latency for makeKeys
		System.out.println("\nIt took " + (endTime - startTime)/1000000 + " milliseconds to create keys.");
		
		//create new socket to connect to server
		Socket socket = new Socket("10.0.2.10", 4444);
	
		//output success 
		System.out.println("\nSocket Connection Successful.");
		
		//init bufferedReader and printStream to send and receive messages through sockets
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintStream output = new PrintStream(socket.getOutputStream());
	
		BufferedReader ClientMessage = new BufferedReader(new InputStreamReader(System.in));
	
		//message = whatever server sent, stores servers public key in servKey
		String message = "";
		String[] servKey = new String [2];
		
		//receives and stores servers public key, sends server client public key
		for (int i = 0; i < 2; i++)
		{
			//convert public key to string, sends to server
			message = keyStuff[i].toString();
			output.println(message);
			
			//receives public key from server, stores in servKey
			message = input.readLine();
			servKey[i] = message;
			System.out.println(servKey[i]);
		}
				
		//stores BigInteger type servKey, N and E variables which make up public key
		BigInteger biN = new BigInteger(servKey[0]);
		BigInteger biE = new BigInteger(servKey[1]);
		
		System.out.println("\nBegin Sending Messages: ");

		//while loop for continual message sending, connection closes if "1" is sent
		while(!(message.equals("1")))
		{
			//authenticate connection for every message sent, if user chose y
			if (doAuth)
			{
				//nanoTime logs latency again
				long startAuth = System.nanoTime();
				//auth function to authenticate server
				auth(keyStuff, servKey, socket);
				long endAuth = System.nanoTime();
				
				System.out.println("\nIt took " + (endAuth - startAuth)/1000000 + " milliseconds to authenticate connection.");
			}
			
			//this whole block takes message, converts to BigInteger, encrypts it, sends to server
			message = ClientMessage.readLine();
			BigInteger biMess = new BigInteger(message);
			//encrypt using E and N calculated in makeKeys function
			BigInteger enc = biMess.modPow(biE, biN);
			output.println(enc);
			
			//block receives encrypted message from server, decrypts it using client private key from keyStuff
			message = input.readLine();
			BigInteger dec = new BigInteger(message);
			//decrypt using D and N from keyStuff
			dec = dec.modPow(keyStuff[2], keyStuff[0]);
			//print decrypted message
			System.out.println(dec);
			
		}
		
		//close readers and scanners
		input.close();
		output.close();
		socket.close();
		userIn.close();
	}
	
	/**
	 * Authenticates connection between client and server
	 * 
	 * @param keyStuff	BigInteger array returned by makeKeys function containing private and public keys
	 * @param serverKey String array sent by server, contains server public key
	 * @param socket	Socket class client socket with IP address and port number
	 * 
	 * @return 			boolean is or is not authenticated
	 */
	public static boolean auth(BigInteger[] keyStuff, String[] serverKey, Socket socket) throws IOException
	{
		//is server authenticated or not
		boolean isServer = false;
		
		//bufferedReader and printStream for socket IO
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintStream output = new PrintStream(socket.getOutputStream());
		
		//plaintext token
		String token = "99108105101110116"; //client in ascii
		//encrypted token
		String encTok = "";
		
		//SYN
		//send server plaintext token
		output.println(token);
		
		//initialize N and E for public key
		BigInteger serverN = new BigInteger(serverKey[0]);
		BigInteger serverE = new BigInteger(serverKey[1]);
		
		//ACK
		//reads encrypted token sent by server, decrypts it using server public key
		encTok = input.readLine();
		BigInteger dec = new BigInteger(encTok);
		dec = dec.modPow(serverE, serverN);
		
		//plaintext token to be sent by server
		String serverToken = "";
		
		//SYN ACK
		//recieves plaintext token from server, encrypts it using client private key, sends back to server
		serverToken = input.readLine();
		BigInteger enc = new BigInteger(serverToken);
		enc = enc.modPow(keyStuff[2], keyStuff[0]);
		output.println(enc.toString());
		
		//if plaintext token == decrypted message that server sent, connection is authenticated
		if(dec.toString().equals(token))
		{
			isServer = true;
		}
		
		return isServer;
	}
	
	/**
	 * Generates random prime numbers to calculate N, E, D which are variables that make up public and private key
	 * 
	 * @param size	int number of bits the keys are
	 * 
	 * @return keyStuff BigInteger array storing N, E, D
	 */
	public static BigInteger[] makeKeys(int size)
	{
		//if user did not input correct bit size, close program
		if (size != 512 && size != 1024 && size != 2048 && size != 4096)
		{
			System.out.println("Please choose correct key size");
			return null;
		}
		
		//divide bit size by 2 for p and q
		int initSize = size/2;
		
		//create random prime number p 
		BigInteger pPrime = BigInteger.probablePrime(initSize, new Random());
		System.out.println("p: " + pPrime);
		
		//create random prime number q
		BigInteger qPrime = BigInteger.probablePrime(initSize, new Random());
		System.out.println("q: " + qPrime);
		
		//multiply p and q together for N
		BigInteger N = pPrime.multiply(qPrime);
		System.out.println("N: " + N);
		
		//phi = (P - 1)(Q - 1)
		BigInteger phi = pPrime.subtract(BigInteger.ONE).multiply(qPrime.subtract(BigInteger.ONE));
		
		//e is random number that must be > 1 and < phi, and cannot be a factor of N
		BigInteger e;
		Random random = new Random();
		do
		{
			e = new BigInteger(phi.bitLength(), random);
		}
		while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
		
		//d = (2(phi(n))+1)/e
		BigInteger d = e.modInverse(phi);
		
		//print e and d
		System.out.println("e: " + e);
		System.out.println("d: " + d);
		
		//initialize keyStuff, store N, E, D, return keyStuff
		BigInteger[] keyStuff = {N, e, d};
		
		return keyStuff;
	}
}
