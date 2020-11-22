import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Scanner;
import java.util.Random;

/**
 * Server class creates server socket, creates socket to respond to client, sends and receives messages 
 * to and from server.
 */
class Server 
{
	public static void main(String arg[]) throws IOException 
	{

		//boolean flags if user wants authentication or confidentiality
		boolean doAuth = false;
		boolean doSecure = false;
		
		//prompt user for bit suze and y/n for auth or confid
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
		System.out.println("\nIt took " + (endTime - startTime)/1000000 + " milliseconds to create keys");
		
		//create new serverSocket, and socket from serverSocket.accept()
		ServerSocket serverSocket = new ServerSocket(4444);
		Socket socket = serverSocket.accept();
	
		System.out.println("\nSocket Connection Successful.");
	
		//init bufferedReader and printStream for client-server IO
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintStream output = new PrintStream(socket.getOutputStream());
	
		BufferedReader ServerMessage = new BufferedReader(new InputStreamReader(System.in));
	
		//message = whatever the client sent, stores clients public key in clientKey
		String message = "";
		String[] clientKey = new String [2];
		
		//receives and stores clients public key, sends client servers public key
		for (int i = 0; i < 2; i++)
		{
			//convert public key to string, sends to client
			message = keyStuff[i].toString();
			output.println(message);
			
			//receives client public key and stores in clientKey
			message = input.readLine();
			clientKey[i] = message;
			System.out.println(clientKey[i]);
		}
		
		//stores BigInteger type servKey, Ne and E vars which make up public key
		BigInteger biN = new BigInteger(clientKey[0]);
		BigInteger biE = new BigInteger(clientKey[1]);
		
		System.out.println("\nBegin Sending Messages: ");
		
		//while loop for continual message sending, connection closes if "1" is sent
		while(!(message.equals("1")))
		{
			
			//authenticate connection for every message sent, if user chose y 
			if(doAuth) 
			{
				//nanoTime logs latency for authentication again
				long startAuth = System.nanoTime();
				//auth function to authenticate client
				auth(keyStuff, clientKey, socket);
				long endAuth = System.nanoTime();
				
				System.out.println("\nIt took " + (endAuth - startAuth)/1000000 + " milliseconds to authenticate connection.");
			}
			
			//this block receives message from client, decrypts it using server private key from keyString
			message = input.readLine();
			BigInteger dec = new BigInteger(message);
			//decrypt using D and N from keyStuff
			dec = dec.modPow(keyStuff[2], keyStuff[0]);
			//prtint decrypted message
			System.out.println(dec);
			
			//takes message from console, converts to BigInteger, encrypts it, sends to client
			message = ServerMessage.readLine();
			BigInteger biMess = new BigInteger(message);
			//encrypt using E and N calculated in makeKeys function
			BigInteger enc = biMess.modPow(biE, biN);
			output.println(enc);
		}
		
		//close readers and scanners
		input.close();
		output.close();
		serverSocket.close();
		socket.close();
		userIn.close();
	}
	
	/**
	 * Authenticates connection between client and server
	 * 
	 * @param keyStuff 	BigInteger array returned by makeKeys function containing private and public keys
	 * @param clientKey String array sent by client, contains server public key
	 * @param socket 	Socket class socket with IP address and port number from serverSocket.accept
	 * 
	 * @return 			boolean is or is not authenticated
	 */
	public static boolean auth(BigInteger[] keyStuff, String[] clientKey, Socket socket) throws IOException
	{
		//is client authenticated or not
		boolean isClient = false;
		
		//bufferedReader and printStream for socket IO
		BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
		PrintStream output = new PrintStream(socket.getOutputStream());
		
		//plaintext token 
		String token = "";
		//encrypted token
		String encTok = "";
		String serverToken = "115101114118101114"; //server in ascii
		
		//SYN ACK
		//receives plaintext token from client, encrypts it using server private key, sends back to client
		token = input.readLine();
		BigInteger enc = new BigInteger(token);
		enc = enc.modPow(keyStuff[2], keyStuff[0]);
		output.println(enc.toString());
		
		//SYN
		//send client plaintext token
		output.println(serverToken);
		
		//init N and E for public key
		BigInteger clientN = new BigInteger(clientKey[0]);
		BigInteger clientE = new BigInteger(clientKey[1]);
		
		//ACK
		//reads encrypted token sent by client, decrypts it using client public key
		encTok = input.readLine();
		BigInteger dec = new BigInteger(encTok);
		dec = dec.modPow(clientE, clientN);
		
		//if plaintext token == decrypted message that client sent, connection is authenticated
		if(dec.toString().equals(serverToken))
		{
			isClient = true;
		}
		
		return isClient;
	}
	
	/**
	 * Generates random prime bumbers to calculate N, E, D which are vars that make up public and private keys
	 * 
	 * @param size	int number of bits the keys are
	 * 
	 * @return keyStuff	BigInteger array that stores N, E, D
	 */
	public static BigInteger[] makeKeys(int size)
	{
		//if user did not input correct bit size, close program
		if (size != 512 && size != 1024 && size != 2048 && size != 4096)
		{
			System.out.println("Please choose correct key size");
			return null;
		}
		
		//divide bit size by 2 for size of p and q
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
		
		//phi = (p - 1)(q - 1)
		BigInteger phi = pPrime.subtract(BigInteger.ONE).multiply(qPrime.subtract(BigInteger.ONE));
		
		//e is a random num that must be greater than 1, less than phi, and cannot be a factor of N
		BigInteger e;
		Random random = new Random();
		do
		{
			e = new BigInteger(phi.bitLength(), random);
		}
		while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE));
		
		//d = (2(phi(n))+1)/2
		BigInteger d = e.modInverse(phi);
		
		//print e and d
		System.out.println("e: " + e);
		System.out.println("d: " + d);
	
		//init keyStuff, store N, E, D, return keyStuff
		BigInteger[] keyStuff = {N, e, d};
		
		return keyStuff;
	}
}
