# RSAPKI
RSA PKI Java implementation

Setting up:

1. Download Client and Server java files on either remote machines or the same machine. 
2. In Client.java, make sure to change the IP address for the socket to match intended IP address for machine that Server.java is on.
  (If Client.java and Server.java are downloaded and running on the same network, make sure you change IP address to that of localhost)
3. Once downloaded, make sure you run Server.java before you run Client.java.
4. In order to send messages, you have to start with the Client, then alternate back and forth, ONE MESSAGE AT A TIME! (The receiving machine will not recognize multiple messages sent consecutively.
