package com.nort721.client;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.X509Certificate;

public class client {

    private static final String REMOTE_HOST = "localhost";
    private static final int REMOTE_PORT = 1234;

    private static final String CERT_PASSWORD = "fJpo3hC5N7DntUnv3";

    private static final boolean SERVER_USES_SELF_SIGNED = true;

    public static void main(String[] args) {
        new client();
    }

    public client() {

        try {

            SSLSocketFactory factory = generateSocketFactory(CERT_PASSWORD.toCharArray());
            SSLSocket sslsocket = (SSLSocket) factory.createSocket(REMOTE_HOST,REMOTE_PORT);

            // explicitly executing a handshake
            sslsocket.startHandshake();

            // What parameters were established?
            System.out.printf("Negotiated Session: %s%n", sslsocket.getSession().getProtocol());
            System.out.printf("Cipher Suite: %s%n", sslsocket.getSession().getCipherSuite());

            BufferedReader input = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));;
            PrintWriter output = new PrintWriter(sslsocket.getOutputStream(), true);

            String str = "test message";
            output.println(str);

            String responseStr = input.readLine();
            System.out.println("server -> " + responseStr);

            output.close();
            input.close();
            sslsocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private SSLSocketFactory generateSocketFactory(char[] password) throws Exception {
        File myCert = new File("/Users/nort/All my files/Java projects/RSAClientDemo/clientCertificate.jks");

        KeyStore keyStore = KeyStore.getInstance(myCert, password);

        TrustManager[] trustManagers;

        if (SERVER_USES_SELF_SIGNED) {

            /*
            Since the server is currently self signing its certificate SSL can't really verify
            it, so we have to accept all certificates to be able to communicate with it

            we also can't expect any customer to run the command to accept our self-signed
            server cert, which is why this is pretty much the only option
             */
            // ToDo check if its possible to whitelist the server's cert instead of accepting just any cert
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
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());

        return context.getSocketFactory();
    }
}
