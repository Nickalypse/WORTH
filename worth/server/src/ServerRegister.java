import java.rmi.server.RemoteServer;
import java.rmi.RemoteException;
import java.io.IOException;
import java.io.FileOutputStream;
import java.security.PrivateKey;
import java.util.Map;


public class ServerRegister extends RemoteServer implements ServerRegisterInterface {
	
	public static final long serialVersionUID = 10000;
	
	// riferimento a chiave privata del server
	private final PrivateKey PRIV_KEY;
	
	// riferimento alle tabelle hash con tutti gli utenti registrati
	private final Map<String,User> USERS_OFFLINE;
	private final Map<String,User> USERS_ONLINE;
	
	
	// COSTRUTTORE
	public ServerRegister(PrivateKey PRIV_KEY, Map<String,User> USERS_OFFLINE, Map<String,User> USERS_ONLINE) {
		this.PRIV_KEY = PRIV_KEY;
		this.USERS_OFFLINE = USERS_OFFLINE;
		this.USERS_ONLINE = USERS_ONLINE;
	}
	
	
	// metodo remoto per la registrazione di un nuovo utente
	public String register(String usernameRSA, String passwordRSA) throws RemoteException {
		
		if(usernameRSA == null || usernameRSA == null)
			return "[RMI:REGISTER] argomenti non possono essere nulli.";
		
		// decodifica argomenti client utilizzando chiave privata del server
		String username = Security.rsa_decripta(PRIV_KEY, usernameRSA);
		if(username == null)
			return "[RMI:REGISTER] username non decodificabile con RSA.";
		String password = Security.rsa_decripta(PRIV_KEY, passwordRSA);
		if(password == null)
			return "[RMI:REGISTER] password non decodificabile con RSA.";
		
		// verifica se username e password sono validi
		if(!Util.checkValidName(username)) return "[RMI:REGISTER] username non valido.";
		if(!Util.checkValidPassword(password)) return "[RMI:REGISTER] password non valida";
		
		// generazione hash della password
		String password_hash = Security.sha256(password);
		if(password_hash == null) return "[RMI:REGISTER] hash della password non generabile.";
		// creazione nuova istanza utente
		User new_user = new User(password_hash);
		
		// [mutua esclusione con ServerMain e ServerCallback]
		synchronized(USERS_ONLINE) {
			// controlla se username è già utilizzato
			if(USERS_OFFLINE.keySet().contains(username)) return "[RMI:REGISTER] username già utilizzato.";
			if(USERS_ONLINE.keySet().contains(username)) return "[RMI:REGISTER] username già utilizzato.";
			// username inserito in tabella
			USERS_OFFLINE.put(username, new_user);
			
			// effettua CALLBACK per aggionare i clients sulla nuova registrazione
			for(String s : USERS_ONLINE.keySet()) {
				User u = USERS_ONLINE.get(s);
				ClientCallbackInterface client = u.getCallbackStub();
				if(client == null) continue;
				
				// codifica AES del messaggio con lo stato dell'utente
				String msgAES = Security.aes_cripta(u.getPasswordAES(), "offline " + username);
				
				try {
					client.notifica_cambiamento_stato_utente(msgAES);
				}
				catch(RemoteException e) {
					// elimina STUB per CALLBACK associato all'utente
					u.setCallbackStub(null);
				}
			}
		}
		
		// salvataggio nuovo utente su disco
		try(FileOutputStream file = new FileOutputStream(ServerMain.PATH_USERS + "/" + username);){
			file.write(password_hash.getBytes());
		}
		catch(IOException e) {
			System.err.println("[SERVER] impossibile creare file utente.");
			System.exit(-1);
		}
		
		System.out.println("[SERVER] new [user:" + username + "]");
		return "[RMI:REGISTER] utente creato.";
	}
	
	
}
