import java.util.ArrayList;


public class User {
	
	// hash della password per l'accesso al profilo
	private final String password_hash;
	// lista di progetti di cui l'utente è membro
	private final ArrayList<String> projects;
	
	// password per la codifica della comunicazione client-server
	private String password_aes;
	// STUB usato dal server per CALLBACK (aggiornamento stato utenti e progetti)
	private ClientCallbackInterface callback_stub;	
	
	
	// COSTRUTTORE
	public User(String password_hash) {
		this.password_hash = password_hash;
		this.projects = new ArrayList<String>();
		
		// utente inizialemente non loggato (nessuna chiave AES, nessuno STUB per CALLBACK)
		this.password_aes	=	null;
		this.callback_stub	=	null;
	}
	
	
	/** GETTER **/
	
	// restituisce l'hash della password dell'utente
	public String getPasswordHash() {
		return this.password_hash;
	}
	
	// restituisce la chiave AES per la comunicazione client-server
	public String getPasswordAES() {
		return this.password_aes;
	}
	
	// restituisce true se l'utente è membro del progetto
	public boolean isMember(String project_name) {
		return this.projects.contains(project_name);
	}
	
	// restituisce la lista dei nomi di progetto di cui l'utente è membro
	public ArrayList<String> getProjects() {
		// crea lista con stessa dimensione della lista projects
		// ==> evita eventuali costi di espansione della lista durante inserimenti
		ArrayList<String> lista = new ArrayList<String>(this.projects.size());
		
		for(String s : this.projects)
			lista.add(s);
		
		return lista;
	}
	
	// restituisce STUB usato dal server per CALLBACK
	public ClientCallbackInterface getCallbackStub() {
		return this.callback_stub;
	}
	
	
	/** SETTER **/
	
	// imposta l'attuale chiave AES per la comunicazione client-server
	public void setPasswordAES(String password_aes) {
		this.password_aes = password_aes;
	}
	
	// aggiunge nome del progetto alla lista dei progetti di cui l'utente è membro
	public void addProject(String project_name) {
		this.projects.add(project_name);
	}
	
	// rimuove nome del progetto alla lista dei progetti di cui l'utente è membro
	public void removeProject(String project_name) {
		this.projects.remove(project_name);
	}
	
	// imposta STUB usato dal server per CALLBACK
	public void setCallbackStub(ClientCallbackInterface callback_stub) {
		this.callback_stub = callback_stub;
	}
	
	
}
