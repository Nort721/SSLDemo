import javax.net.ssl.*;
import java.io.*;
import java.security.*;

public class client {

    private static final String REMOTE_HOST = "localhost";
    private static final int REMOTE_PORT = 1234;
    private static final String SSL_PASSWORD = "yourPassword";

    public static void main(String[] args) {
        new client();
    }

    public client() {

        try {

            SSLSocketFactory factory = generateSocketFactory(SSL_PASSWORD.toCharArray());
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
        } catch(Exception e) {
            e.printStackTrace();
        }

    }

    private SSLSocketFactory generateSocketFactory(char[] password) throws Exception {
        File myCert = new File("myCertificate.jks");

        KeyStore keyStore = KeyStore.getInstance(myCert, password);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
        keyManagerFactory.init(keyStore, password);

        SSLContext context = SSLContext.getInstance("TLS");// "SSL" or "TLS"
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        return context.getSocketFactory();
    }
}
