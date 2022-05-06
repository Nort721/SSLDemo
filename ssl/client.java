import javax.net.ssl.*;
import java.io.*;
import java.security.*;

public class client {

    public static void main(String[] args) {
        new client();
    }

    public client() {

        try {

            SSLSocketFactory factory = generateSocketFactory("yourPassword".toCharArray());
            SSLSocket sslsocket=(SSLSocket) factory.createSocket("localhost",1234);

            BufferedReader input = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));;
            PrintWriter output = new PrintWriter(sslsocket.getOutputStream(), true);

            String str = "test message";
            output.println(str);

            String responseStr = input.readLine();
            System.out.println(responseStr);

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
