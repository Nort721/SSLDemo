import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class server {

    public static void main(String[] args) {
        new server();
    }

    public server() {

        try {

            SSLServerSocketFactory factory = generateServerFactory("yourPassword".toCharArray());
            SSLServerSocket sslserversocket = (SSLServerSocket) factory.createServerSocket(1234);

            System.out.println("listening to encrypted connections . . .");

            while (true) {

                SSLSocket sslsocket = (SSLSocket) sslserversocket.accept();

                System.out.println(" -> encrypted connection received from " + sslsocket.getInetAddress().getHostAddress());

                BufferedReader in = new BufferedReader(new InputStreamReader(sslsocket.getInputStream()));;
                PrintWriter out = new PrintWriter(sslsocket.getOutputStream(), true);

                String input = in.readLine();
                System.out.println("payload -> " + input);
                out.println(input.toUpperCase());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    private SSLServerSocketFactory generateServerFactory(char[] password) throws Exception {
        File myCert = new File("myCertificate.jks");

        KeyStore keyStore = KeyStore.getInstance(myCert, password);

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(keyStore);

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("NewSunX509");
        keyManagerFactory.init(keyStore, password);

        SSLContext context = SSLContext.getInstance("TLS");// "SSL" or "TLS"
        context.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        return context.getServerSocketFactory();
    }
}
