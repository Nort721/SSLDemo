import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;

public class server {

    private static final int PORT = 1234;
    private static final String SSL_PASSWORD = "yourPassword";

    public static void main(String[] args) {
        new server();
    }

    public server() {

        try {

            SSLServerSocketFactory factory = generateServerFactory(SSL_PASSWORD.toCharArray());
            SSLServerSocket sslserversocket = (SSLServerSocket) factory.createServerSocket(PORT);
            sslserversocket.setNeedClientAuth(true);

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
