import java.rmi.RemoteException;
import java.rmi.server.RemoteServer;
import java.security.PrivateKey;
import java.util.Map;


public class ServerCallback extends RemoteServer implements ServerCallbackInterface {
	
	private final static long serialVersionUID = 987654321;
	
	// riferimento a chiave privata RSA del server
	private final PrivateKey PRIV_KEY;
	
	// riferimenti a tabelle hash che associano l'istanza dell'utente allo username
	private final Map<String,User> USERS_OFFLINE;
	private final Map<String,User> USERS_ONLINE;
	
	// riferimento a tabella hash che associa l'istanza del progetto al nome
	private final Map<String,Project> PROJECTS;
	
	
	// COSTRUTTORE
	public ServerCallback(PrivateKey PRIV_KEY, Map<String,Project> PROJECTS,
	Map<String,User> USERS_OFFLINE, Map<String,User> USERS_ONLINE) {
		super();
		this.PRIV_KEY = PRIV_KEY;
		this.USERS_OFFLINE = USERS_OFFLINE;
		this.USERS_ONLINE = USERS_ONLINE;
		this.PROJECTS = PROJECTS;
	}
	
	
	// metodo remoto per la registrazione dell'utente alle CALLBACK di aggiornamento
	public String registrazione_callback(ClientCallbackInterface client, String dataRSA) throws RemoteException {
		
		if(client == null || dataRSA == null) return "[RMI:CALLBACK] argomenti non possono essere nulli";
		
		String data = Security.rsa_decripta(PRIV_KEY, dataRSA);
		if(data == null) return "[RMI:CALLBACK] impossibile effettuare decodifica RSA";
		
		// suddivisione messaggio in username e password
		String cmd[] = data.split(" ");
		
		User u;
		String users_list_aes;
		
		// [mutua esclusione con ServerMain e ServerRegister]
		synchronized(USERS_ONLINE) {
			// estrazione istanza utente tra quelli loggati
			u = USERS_ONLINE.get(cmd[0]);
			if(u == null) return "[RMI:CALLBACK] utente non loggato";
			
			// verifica correttezza password
			if(!Security.sha256(cmd[1]).equals(u.getPasswordHash()))
				return "[RMI:CALLBACK] password errata.";
			// verifica se STUB dell'utente è già registrato
			if(u.getCallbackStub() != null)
				return "[RMI:CALLBACK] stub già associato all'utente";
			
			// associa STUB per CALLBACK all'utente
			u.setCallbackStub(client);
			
			
			String users_list = "";
			// creazione stringa con lista username degli utenti disconnessi
			for(String user : USERS_OFFLINE.keySet())
				users_list += user + "\n";
			// creazione stringa con lista username degli utenti connessi
			users_list += ".\n";
			for(String user : USERS_ONLINE.keySet())
				users_list += user + "\n";
			
			// codifica lista utenti con chiave AES della comunicazione client-server
			users_list_aes = Security.aes_cripta(u.getPasswordAES(), users_list);
			if(users_list_aes == null)
				return "[RMI:CALLBACK] impossibile effettuare codifica AES della lista utenti";
			
			
			// scansione dei progetti di cui l'utente è membro
			for(String project : u.getProjects()) {
				// estrazione istanza del progetto
				Project p = PROJECTS.get(project);
				
				// concatena dati di accesso alla chat del progetto
				String msg = project + " " + p.getChatIP() + " " + p.getChatAESKey();
				// codifica dati con chiave AES della comunicazione client-server
				String msgAES = Security.aes_cripta(u.getPasswordAES(), msg);
				
				try {
					// effettua CALLBACK per comunicare dati di accesso alla chat del progetto
					client.notifica_nuova_chat_progetto(msgAES);
				}
				catch(RemoteException e) {
					// elimina STUB per CALLBACK associato all'utente
					u.setCallbackStub(null);
				}
			}
		}
		
		return "[RMI:CALLBACK] registrazione effettuata\n" + users_list_aes;
	}
	
	
}
