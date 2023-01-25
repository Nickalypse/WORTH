import java.rmi.RemoteException;
import java.rmi.server.RemoteObject;
import java.io.IOException;
import java.util.List;
import java.util.Map;


public class ClientCallback extends RemoteObject implements ClientCallbackInterface {
	
	private static final long serialVersionUID = 123456789;
	
	// riferimento a tabella che associa ai nomi dei progetti i thread in ascolto dei messaggi delle corrispettive chat	
	private final Map<String, ClientChat> CHAT_READERS;
	
	private final List<String> USERS_OFFLINE;
	private final List<String> USERS_ONLINE;
	
	private final String AES_KEY;
	
	
	// COSTRUTTORE
	public ClientCallback(String AES_KEY, Map<String, ClientChat> CHAT_READERS,
	List<String> USERS_OFFLINE, List<String> USERS_ONLINE) throws RemoteException {
		super();
		this.AES_KEY = AES_KEY;
		this.CHAT_READERS = CHAT_READERS;
		this.USERS_OFFLINE = USERS_OFFLINE;
		this.USERS_ONLINE = USERS_ONLINE;
		// svuota le liste di utenti registrati
		this.USERS_OFFLINE.clear();
		this.USERS_ONLINE.clear();
	}
	
	
	/** SERVER --> CLIENT **/
	
	public void notifica_cambiamento_stato_utente(String msgAES) throws RemoteException {
		
		// decodifica AES del messaggio
		String msg = Security.aes_decripta(AES_KEY, msgAES);
		if(msg == null) return;
		
		// separa stato dell'utente da username
		String[] data = msg.split(" ");
		
		// controlla nuovo stato dell'utente
		if(data[0].equals("online")) {
			// sposta utente da lista disconnessi a lista connessi
			synchronized(USERS_ONLINE) {
				USERS_OFFLINE.remove(data[1]);
				USERS_ONLINE.add(data[1]);
			}
		}
		else {
			// sposta utente da lista connessi a lista disconnessi
			synchronized(USERS_ONLINE) {
				USERS_ONLINE.remove(data[1]);
				USERS_OFFLINE.add(data[1]);
			}
		}
	}
	
	public void notifica_nuova_chat_progetto(String msgAES) throws RemoteException {
		
		// decodifica AES del messaggio
		String msg = Security.aes_decripta(AES_KEY, msgAES);
		if(msg == null) return;
		
		// separazione dati della chat del progetto dalla risposta testuale
		String[] data = msg.split(" ");
		
		// gestione chat del progetto
		try {
			// istanzia nuovo thread per la gestione della chat
			ClientChat th = new ClientChat(data[1], data[2]);
			// esegui thread che gestisce chat
			th.start();
			// aggiungi progetto e gestore associato alla tabella
			synchronized(CHAT_READERS) {
				CHAT_READERS.put(data[0], th);
			}
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile inizializzare connessione multicast.");
		}
	}
	
	public void notifica_chiusura_chat_progetto(String msgAES) throws RemoteException {
		
		// decodifica AES del messaggio
		String msg = Security.aes_decripta(AES_KEY, msgAES);
		if(msg == null) return;
		
		ClientChat th;
		// rimuovi progetto e gestore associato dalla tabella
		synchronized(CHAT_READERS) {
			th = CHAT_READERS.remove(msg);
		}
		// termina thread che gestisce chat
		if(th != null) th.interrupt();
	}
	
	
}
