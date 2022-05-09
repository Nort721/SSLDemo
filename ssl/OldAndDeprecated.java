package com.nort721.client;

import javax.net.ssl.*;
import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class OldAndDeprecated {
    /**
     * Generates a socket factory that uses the client's certificate
     * and whitelists the server one from the resources folder
     *
     * ISSUE: This requires you to hold the server's certificate inside the client jar
     * which is a bad idea
     * @return A custom SSLSocketFactory
     */
    @Deprecated
    private SSLSocketFactory generateSocketFactoryOld() throws Exception {
        // Get the client's keystore
        String clientCertPassword = "fJpo3hC5N7DntUnv3";
        File clientKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("clientCertificate.jks").toURI());
        KeyStore clientKeyStore = KeyStore.getInstance(clientKeystoreFile, clientCertPassword.toCharArray());

        // Get the server's keystore
        String serverCertPassword = "HBTHDgsDSN3uwjFr5";
        File serverKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("serverCertificate.jks").toURI());
        KeyStore serverKeyStore = KeyStore.getInstance(serverKeystoreFile, serverCertPassword.toCharArray());

        // Whitelist the server's certificate on the generated client-sockets
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", "SunJSSE");
        trustManagerFactory.init(serverKeyStore);
        X509TrustManager x509TrustManager = null;
        for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager) {
                x509TrustManager = (X509TrustManager) trustManager;
                break;
            }
        }

        // If the whitelisting gone wrong, throw an exception
        if (x509TrustManager == null) throw new NullPointerException();

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
        sslContext.init(new KeyManager[]{x509KeyManager}, new TrustManager[]{x509TrustManager}, null);

        return sslContext.getSocketFactory();
    }

    /**
     * Generates an SSLSocketFactory that uses the client's certificate from the resources
     * folder and allows for any server certificate including any self-signed one, doing
     * this is pretty insecure but at least it doesn't require us to hold our server's
     * keystore inside the jar
     *
     * ISSUE: This will just converse with every server assuming its the correct one, bad idea
     * @param usingSelfSignedCerts toggle weather our target server uses a self-signed certificate
     * @return a custom SSLSocketFactory
     */
    @Deprecated
    private SSLSocketFactory generateSocketFactoryOldOld(boolean usingSelfSignedCerts) throws Exception {
        File clientKeystoreFile = new File(ClassLoader.getSystemClassLoader().getResource("clientCertificate.jks").toURI());

        String clientCertPassword = "fJpo3hC5N7DntUnv3";
        KeyStore keyStore = KeyStore.getInstance(clientKeystoreFile, clientCertPassword.toCharArray());

        TrustManager[] trustManagers;

        if (usingSelfSignedCerts) {

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
        keyManagerFactory.init(keyStore, clientCertPassword.toCharArray());

        SSLContext context = SSLContext.getInstance("TLS");// "SSL" or "TLS"
        context.init(keyManagerFactory.getKeyManagers(), trustManagers, null);
        HttpsURLConnection.setDefaultSSLSocketFactory(context.getSocketFactory());

        return context.getSocketFactory();
    }
}
