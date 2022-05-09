package com.nort721.client;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class client {

    private static final String REMOTE_HOST = "localhost";
    private static final int REMOTE_PORT = 1234;

    private static final byte[]
            SERVER_PINNED_HASH = {-88, -120, -3, -84, 7, 116, -12, -12, -120, 57, -106, -27, 14, 79, 12, 87, 93, -60, 45, -81, 95, -34, 62, 39, 69, -28, 117, 27, -126, 12, -97, 1};

    // entry point
    public static void main(String[] args) {
        new client();
    }

    public client() {

        try {

            SSLSocketFactory factory = generateSocketFactory();
            SSLSocket sslsocket = (SSLSocket) factory.createSocket(REMOTE_HOST, REMOTE_PORT);

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

    /**
     * Generates a socket factory that uses the client's certificate
     * and compares the received server certificate hash to our pinned hash
     * @return A custom SSLSocketFactory
     */
    private SSLSocketFactory generateSocketFactory() throws Exception {
        // Get the client's keystore
        String clientCertPassword = "fJpo3hC5N7DntUnv3";
        File clientKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("clientCertificate.jks").toURI());
        KeyStore clientKeyStore = KeyStore.getInstance(clientKeystoreFile, clientCertPassword.toCharArray());

        TrustManagerFactory tmf = null;

        try {
            // Default is likely to be PKIX, but could be SunX509 on some systems
            String def = TrustManagerFactory.getDefaultAlgorithm();
            tmf = TrustManagerFactory.getInstance(def);

            // Using null here initialises the default trust store, which in this case is loaded from the above properties
            tmf.init((KeyStore) null);
        } catch (KeyStoreException e) {
            System.err.println("Keystore Exception: " + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Unable to obtain a trust manager: " + e.getMessage());
        }

        // Get hold of the default trust manager - will only return one as we only specified one algorithm above.
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];

        // Wrap it in your own class.
        X509TrustManager pinningX509TrustManager = new X509TrustManager() {

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                // Pass through
                return defaultTrustManager.getAcceptedIssuers();
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain,
                                           String authType) throws CertificateException {
                // Use default trust manager to verify certificate chain
                //defaultTrustManager.checkServerTrusted(chain, authType);

                MessageDigest messageDigest;
                try {
                    messageDigest = MessageDigest.getInstance("SHA-256");
                    if (!Arrays.equals(messageDigest.digest(chain[0].getEncoded()), SERVER_PINNED_HASH)) {
                        throw new CertificateException("The provided server certificate does not match pinned certificate");
                    }
                } catch (NoSuchAlgorithmException | CertificateException e) {
                    e.printStackTrace();
                }

            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain,
                                           String authType) throws CertificateException {
                // We could validate client certs here, but it is out of scope for what we want to do
                throw new CertificateException("This trust manager does not verify client certificates");
            }
        };

        // Setup the client's keystore
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        keyManagerFactory.init(clientKeyStore, clientCertPassword.toCharArray());
        X509KeyManager x509KeyManager = null;
        for (KeyManager keyManager : keyManagerFactory.getKeyManagers()) {
            if (keyManager instanceof X509KeyManager) {
                x509KeyManager = (X509KeyManager) keyManager;
                break;
            }
        }

        // If setting up the client's keystore gone wrong, throw an exception
        if (x509KeyManager == null) throw new NullPointerException();

        // set up the SSL Context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(new KeyManager[]{x509KeyManager}, new TrustManager[]{pinningX509TrustManager}, null);

        return sslContext.getSocketFactory();
    }
}
