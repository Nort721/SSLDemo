package com.nort721.server;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class server {

    private static final int PORT = 1234;
    private static final String CERT_PASSWORD = "HBTHDgsDSN3uwjFr5";

    // <---> security settings <--->
    private static final boolean REQUIRE_CLIENT_AUTH = false;

    // <---> properties <--->
    private static final boolean USING_SELF_SIGNED = true;

    public static void main(String[] args) {
        new server();
    }

    public server() {

        try {

            SSLServerSocketFactory factory = generateServerFactory(CERT_PASSWORD.toCharArray());
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

    private SSLServerSocketFactory generateServerFactory(char[] password) throws Exception {
        File myCert = new File("/Users/nort/All my files/Java projects/RSAServerDemo/serverCertificate.jks");

        KeyStore keyStore = KeyStore.getInstance(myCert, password);

        TrustManager[] trustManagers;

        if (REQUIRE_CLIENT_AUTH && USING_SELF_SIGNED) {

            /*
            Since we are currently self singing our certificates SSL can't really verify
            them, so we have to accept all certificates, so enabling client auth may be
            pointless, however it does increase security by a bit since some clients wouldn't
            agree to auth at all so at least we filter those
             */
            // ToDo maybe we can accept the specific cert that all client jars will use on our com.nort721.server.server
            // ToDo instead of accepting just any cert
            trustManagers = new TrustManager[] {
                    new X509TrustManager() {
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new X509Certificate[0];
                        }
                        public void checkClientTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                        public void checkServerTrusted(
                                java.security.cert.X509Certificate[] certs, String authType) {
                        }
                    }
            };

        } else {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            trustManagers = trustManagerFactory.getTrustManagers();
        }

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
        keyManagerFactory.init(keyStore, password);

        SSLContext context = SSLContext.getInstance("TLS");// "SSL" or "TLS"
        context.init(keyManagerFactory.getKeyManagers(), trustManagers, null);

        return context.getServerSocketFactory();
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
