package com.nort721.server;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class server {

    private static final int PORT = 1234;

    // <---> security settings <--->
    private static final boolean REQUIRE_CLIENT_AUTH = true;

    // entry point
    public static void main(String[] args) {
        new server();
    }

    public server() {

        try {

            SSLServerSocketFactory factory = generateServerFactory();
            SSLServerSocket sslserversocket = (SSLServerSocket) factory.createServerSocket(PORT);
            sslserversocket.setNeedClientAuth(REQUIRE_CLIENT_AUTH);

            System.out.println("listening to secure connections . . .");

            while (true) {
                SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();
                ClientHandler clientHandler = new ClientHandler(sslsocket);
                clientHandler.start();
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    /**
     * Generates a server socket factory that uses the server's certificate
     * and whitelists the client one from the resources folder
     * @return a custom SSLServerSocketFactory
     */
    private SSLServerSocketFactory generateServerFactory() throws Exception {
        // Get the server's keystore
        String serverCertPassword = "HBTHDgsDSN3uwjFr5";
        File serverKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("serverCertificate.jks").toURI());
        KeyStore serverKeyStore = KeyStore.getInstance(serverKeystoreFile, serverCertPassword.toCharArray());

        // Get the client's keystore
        String clientCertPassword = "fJpo3hC5N7DntUnv3";
        File clientKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("clientCertificate.jks").toURI());
        KeyStore clientKeyStore = KeyStore.getInstance(clientKeystoreFile, clientCertPassword.toCharArray());

        // Whitelist the client's certificate on the generated servers
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        trustManagerFactory.init(clientKeyStore);
        X509TrustManager x509TrustManager = null;
        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                x509TrustManager = (X509TrustManager) trustManager;
                break;
            }
        }

        // If the whitelisting gone wrong, throw an exception
        if (x509TrustManager == null) throw new NullPointerException();

        // Setup the server's keystore
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        keyManagerFactory.init(serverKeyStore, serverCertPassword.toCharArray());
        X509KeyManager x509KeyManager = null;
        for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
            if (keyManager instanceof X509KeyManager) {
                x509KeyManager = (X509KeyManager) keyManager;
                break;
            }
        }

        // If setting up the server's keystore gone wrong, throw an exception
        if (x509KeyManager == null) throw new NullPointerException();

        // set up the SSL Context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[]{x509KeyManager}, new TrustManager[]{x509TrustManager}, null);

        return sslContext.getServerSocketFactory();
    }

    // handle each socket client on separate thread
    class ClientHandler extends Thread {

        SSLSocket socket;
        BufferedReader input;
        PrintWriter output;

        public ClientHandler(SSLSocket socket) {
            this.socket = socket;

            try {
                input = new BufferedReader(new InputStreamReader(socket.getInputStream()));;
                output = new PrintWriter(socket.getOutputStream(), true);
            } catch (IOException e) {
                System.err.println("Error creating streams: " + e.getMessage());
            }

            System.out.println(" -> established secure connection with " + socket.getInetAddress().getHostAddress());
        }

        @Override
        public void run() {
            try {

                String data = input.readLine();
                System.out.println(socket.getInetAddress().getHostAddress() + " -> " + data);

                String reply = data.toUpperCase();
                System.out.println("replying to " + socket.getInetAddress().getHostAddress() + " -> " + reply);
                output.println(reply);

                // close everything when were done
                output.close();
                input.close();
                socket.close();

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

}
