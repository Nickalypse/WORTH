import java.net.InetAddress;
import java.net.MulticastSocket;
import java.net.DatagramPacket;
import java.io.IOException;
import java.util.LinkedList;


public class ClientChat extends Thread {
	
	// indirizzo della chat Multicast 
	private final InetAddress ADDRESS;
	// socket per la ricezione dei messaggi
	private final MulticastSocket SOCKET;
	
	// indirizzo IP Multicast della chat di progetto
	private final String CHAT_IP;
	// chaive AES per decodifica messaggi inviati nel gruppo multicast
	private final String CHAT_AES_KEY;
	// lista di messaggi decodificati ricevuti non visualizzati dall'utente
	private final LinkedList<String> MESSAGES;
	
	
	// COSTRUTTORE
	public ClientChat(String chat_ip, String chat_aes_key) throws IOException {
		
		// istanzia indirizzo data la stringa con ip
		this.ADDRESS = InetAddress.getByName(chat_ip);
		// istanzia socket multicast per ricezione messaggi
		this.SOCKET = new MulticastSocket(ClientMain.PORT_MULTICAST);
		// consenti di istanziare altri socket sulla stessa porta
		this.SOCKET.setReuseAddress(true);
		// entra a far parte del gruppo multicast (obbligatorio per ricevere)
		this.SOCKET.joinGroup(this.ADDRESS);
		
		this.CHAT_IP = chat_ip;
		this.CHAT_AES_KEY = chat_aes_key;
		this.MESSAGES = new LinkedList<String>();
	}
	
	
	/** METODI THREAD ***************************************************************************************/
	
	public void run() {
		try {
			// ciclo interroto con interrupt dopo logout dell'utente
			while(true) {
				
				// allocazione buffer per ricezione messaggi
				byte[] buffer = new byte[ClientMain.SIZE_BUFFER];
				// creazione pacchetto UDP per la ricezione
				DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
				
				// ricezione messaggio dal gruppo multicast
				SOCKET.receive(packet);
				
				// conversione array di byte in stringa
				String msgAES = new String(packet.getData()).trim();
				// decodifica AES del messaggio
				String msg = Security.aes_decripta(CHAT_AES_KEY, msgAES);
				// scarta messaggi non codificati con la chiave AES associata al progetto
				if(msg == null) continue;
								
				// messaggio aggiunto alla lista messaggi non visualizzati
				synchronized(MESSAGES) {
					MESSAGES.addLast(msg);
				}
			}			
		}
		catch(IOException e) {}
	}
	
	// gestione interruzione con chiusura socket
	public void interrupt(){
		super.interrupt();
		
		// lascia gruppo Multicast
		try {SOCKET.leaveGroup(ADDRESS);} catch(IOException e) {}
		
		// termina socket UDP in ascolto
		// ==> SOCKET.receive() solleva IOException nel metodo run()
		SOCKET.close();
	}
	
	/** METODI LOCALI ***************************************************************************************/
	
	// restituisce stringa con IP della chat
	public String getChatIP() {
		return CHAT_IP;
	}
	
	// restituisce stringa con chiave AES della chat
	public String getChatAESKey() {
		return CHAT_AES_KEY;
	}
	
	// restituisce array con i nuovi messaggi decodificati ricevuti
	public String[] getNewMessages() {
		
		String[] new_messages = new String[MESSAGES.size()];
				
		synchronized(MESSAGES) {
			// rimuovi messaggi dalla lista e inseriscili nell'array
			for(int i=0; i<new_messages.length; i++)
				new_messages[i] = MESSAGES.pop();
		}
		
		return new_messages;
	}
	
	// invia messaggio nella chat multicast
	public void sendMessages(String msg) {
		
		String msgAES = Security.aes_cripta(CHAT_AES_KEY, msg.trim());
		if(msgAES == null) {
			System.err.println("[ERRORE] impossibile effettuare codifica AES del messaggio multicast.");
			System.exit(-1);
		}
		
		byte[] buffer = msgAES.getBytes();
		// creazione pacchetto UDP
		DatagramPacket packet = new DatagramPacket(buffer, buffer.length, ADDRESS, ClientMain.PORT_MULTICAST);
		
		// istanzia MulticastSocket per invio del messaggio in chat
		// utilizzato un secondo socket per garantire THREAD-SAFETY
		try(MulticastSocket SOCKET_SEND = new MulticastSocket()) {
			// pacchetti gestiti localmente
			SOCKET_SEND.setTimeToLive(0);
			// invia pacchetto UDP
			SOCKET_SEND.send(packet);
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile inviare messaggio multicast.");
			System.exit(-1);
		}
	}
	
	
}
