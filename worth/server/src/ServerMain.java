import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.net.InetSocketAddress;
import java.rmi.*;
import java.rmi.server.*;
import java.rmi.registry.*;
import java.security.PrivateKey;
import java.util.Iterator;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.LinkedList;


public class ServerMain {
	
	/** COSTANTI STATICHE *************************************************************************************************/
	
	public final static String	PATH_HOME		=	"./server/home";
	public final static String	PATH_IP			=	PATH_HOME + "/_ip";
	public final static String	PATH_KEYS		=	PATH_HOME + "/_keys";
	public final static String	PATH_USERS		=	PATH_HOME + "/users";
	public final static String	PATH_PROJECTS	=	PATH_HOME + "/projects";
	public final static String	RMI_REGISTER	=	"REGISTER";
	public final static String	RMI_CALLBACK	=	"CALLBACK";
	
	public final static int		PORT_REGISTRY	=	54000;
	public final static int		PORT_TCP		=	55555;
	public final static int		PORT_MULTICAST	=	56000;
	public final static int		SIZE_SHA256		=	44;
	public final static int		SIZE_BUFFER		=	1024;
	
	
	/** VARIABILI LOCALI **************************************************************************************************/
	
	// chiave privata RSA del server
	private final PrivateKey PRIV_KEY;
	
	// primo indirizzo IP Multicast libero caricato da file
	private final int[] IP_NEXT;
	
	// lista di IP Multicast assegnati a progetti poi cancellati
	private final LinkedList<String> IP_FREE;
	
	// tabelle hash che associano l'istanza dell'utente allo username
	private final HashMap<String,User> USERS_OFFLINE;
	private final HashMap<String,User> USERS_ONLINE;
	
	// tabella hash che associa l'istanza del progetto al nome del progetto
	private final HashMap<String,Project> PROJECTS;
	
	private ServerSocketChannel SOCKET;
	private Selector SELECTOR;
	private ServerCallback STUB_CALLBACK;
	
	
	/** COSTRUTTORE *******************************************************************************************************/
	
	public ServerMain() {
		this.PRIV_KEY		=	carica_chiave_privata();
		this.IP_NEXT		=	carica_next_ip();
		this.IP_FREE		=	carica_free_ip();
		this.USERS_OFFLINE	=	new HashMap<String,User>();
		this.USERS_ONLINE	=	new HashMap<String,User>();
		this.PROJECTS		=	new HashMap<String,Project>();
	}
	
	
	/** MAIN **************************************************************************************************************/
	
	public static void main(String[] args) {
		ServerMain server = new ServerMain();
		server.START();
	}
	
	
	/** METODI STATICI ****************************************************************************************************/
	
	// lettura chiave privata RSA del server da file
	private static PrivateKey carica_chiave_privata() {
		PrivateKey priv_key = Security.rsa_importa_priv_key(PATH_KEYS);
		if(priv_key == null) {
			System.err.println("[ERRORE] chiave privata non trovata o danneggiata.");
			System.exit(-1);
		}
		return priv_key;
	}
	
	// lettura nuovo indirizzo IP multicast
	private static int[] carica_next_ip() {
		
		String[] ip_data = null;
		// lettura password hash contenuto nel file
		try(FileInputStream in = new FileInputStream(PATH_IP + "/next_ip")){
			byte[] buffer = new byte[16];
			in.read(buffer);
			ip_data = new String(buffer).trim().split("\\.");
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile accedere a file \"next_ip\".");
			System.exit(-1);
		}
		
		int[] ip = new int[4];
		// conversione stringhe in interi
		for(int i=0; i<4; i++)
			ip[i] = Integer.parseInt(ip_data[i]);
		
		return ip;
	}
	
	// lettura lista IP multicast liberi (assegnati a progetti cancellati)
	private static LinkedList<String> carica_free_ip() {
		
		LinkedList<String> lista = new LinkedList<String>();
		
		// lettura stringa con lista di indirizzi IP liberi
		try(BufferedReader in = new BufferedReader(new FileReader(PATH_IP + "/free_ip"))){
			String s = in.readLine();
			while(s != null) {
				s = s.trim();
				// inserisci IP in lista
				if(!s.equals("")) lista.push(s);
				// lettura prossimo IP da file
				s = in.readLine();
			}
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile accedere a file \"free_ip\".");
			System.exit(-1);
		}
		
		return lista;
	}
	
	// invia testo in chiaro al client
	private static void invia_messaggio_client(SocketChannel client, String text) throws IOException {
		String msg = "[SERVER] " + text;
		// alloca buffer contente il messaggio in chiaro
		ByteBuffer buffer = ByteBuffer.wrap(msg.getBytes(Security.CHAR_SET));
		// invio il messaggio al client
		client.write(buffer);
	}
	// invia testo codificato con AES al client
	private static void invia_messaggio_aes_client(SocketChannel client, String aes_key, String text) throws IOException {
		String msg = "[SERVER] " + text;
		// codifica del messaggio con AES
		String msgAES = Security.aes_cripta(aes_key, msg);
		if(msgAES == null) throw new IOException();
		
		// alloca buffer contente il messaggio codificato
		ByteBuffer buffer = ByteBuffer.wrap(msgAES.getBytes());
		// invio il messaggio codificato al client
		client.write(buffer);
	}
	
	
	/** METODI LOCALI *****************************************************************************************************/
	
	private void START() {
		
		carica_dati_persistenti();
		pubblica_servizi_RMI();
		inizializza_server_tcp();
				
		while(true) {
			try {SELECTOR.select();}
			catch(IOException e) {
				System.err.println("[ERRORE] impossibile operare sul selettore.");
				break;
			}
			Iterator<SelectionKey> iterator = SELECTOR.selectedKeys().iterator();
			while(iterator.hasNext()) {
				SelectionKey key = iterator.next();
				iterator.remove();
				try {
					if(!key.isValid())		throw new IOException();
					if(key.isAcceptable())	gestione_selector_acceptable(key);
					if(key.isReadable())	gestione_selector_readable(key);
				}
				catch(IOException e) {
					gestisci_disconnessione(key);
				}
			}
		}
		// terminazione server
		try {
			SELECTOR.close();
			SOCKET.socket().close();
			SOCKET.close();
		}
		catch(IOException e) {}
		System.exit(0);
	}
	
	// lettura utenti, progetti e cards da files
	private void carica_dati_persistenti() {
		
		/** IMPORTA UTENTI **/
		
		// apri directory con files degli utenti
		File dir = new File(PATH_USERS);
		if(!dir.isDirectory()) {
			System.err.println("[ERRORE] USER_PATH non è una directory.");
			System.exit(-1);
		}
		
		long count = 0;
		// scansione files degli utenti
		for(String file_name : dir.list()) {
			
			byte[] data = new byte[SIZE_SHA256];
			
			// lettura hash della password contenuto nel file
			try(FileInputStream f = new FileInputStream(PATH_USERS + "/" + file_name)){
				f.read(data);
			}
			catch(IOException e) {
				System.err.println("[ERRORE] impossibile accedere a file utente.");
				System.exit(-1);
			}
			
			// conversione array di byte in stringa
			String password_hash = new String(data).trim();
			// creazione istanza utente
			User u = new User(password_hash);
			// utente aggiunto a tabella hash
			USERS_OFFLINE.put(file_name, u);
			count++;
		}
		System.out.printf("[SERVER] IMPORTATI %d UTENTI\n", count);
		
		/** IMPORTA PROGETTI **/
		
		// apri directory dei progetti
		dir = new File(PATH_PROJECTS);
		if(!dir.isDirectory()) {
			System.err.println("[ERRORE] PATH_PROJECTS non è una directory.");
			System.exit(-1);
		}
		
		count = 0;
		for(String dir_name : dir.list()) {
			
			String project_path = PATH_PROJECTS + "/" + dir_name;
						
			String[] members = null;
			// lettura array serializzato con membri del progetto
			try(ObjectInputStream in = new ObjectInputStream(new FileInputStream(project_path + "/_members"))){
				members = (String[]) in.readObject();
			}
			catch(Exception e) {
				System.err.println("[ERRORE] impossibile accedere al file \"_members\".");
				System.exit(-1);
			}
			
			String[] chat_data = null;
			// lettura IP multicast e chiave AES della chat del progetto
			try(FileInputStream in = new FileInputStream(project_path + "/_chat")){
				byte[] buffer = new byte[64];
				in.read(buffer);
				chat_data = new String(buffer).trim().split("\n");
			}
			catch(Exception e) {
				System.err.println("[ERRORE] impossibile accedere al file \"_chat\".");
				System.exit(-1);
			}
			
			// istanzia progetto che conterrà dati estratti dal file
			Project p = new Project(chat_data[0], chat_data[1]);
			
			for(String username : members) {
				// associa progetto ad ogni utente membro
				USERS_OFFLINE.get(username).addProject(dir_name);
				// associa utente membro al progetto
				p.addMember(username);
			}
			
			/** IMPORTA CARDS DEL PROGETTO **/
			
			File project_dir = new File(project_path);
			
			for(String card_name : project_dir.list()) {
				// ignora file speciali (non sono cards)
				if(card_name.equals("_members")) continue;
				if(card_name.equals("_chat")) continue;
				
				Card c = null;
				// lettura card serializzata
				try(ObjectInputStream in = new ObjectInputStream(new FileInputStream(project_path + "/" + card_name))){
					c = (Card) in.readObject();
				}
				catch(Exception e) {
					System.err.println("[ERRORE] impossibile leggere card da file.");
					System.exit(-1);
				}
				// card aggiunta all'istanza del progetto
				p.addCard(card_name, c);
			}
			
			// progetto aggiunto alla tabella hash
			PROJECTS.put(dir_name, p);
			count++;
		}
		System.out.printf("[SERVER] IMPORTATI %d PROGETTI\n", count);
	}
	
	// pubblica servizio RMI per la registrazione di nuovi utenti
	private void pubblica_servizi_RMI() {
		
		// istanzia oggetto con servizio CALLBACK sullo stato degli utenti
		STUB_CALLBACK = new ServerCallback(PRIV_KEY, PROJECTS, USERS_OFFLINE, USERS_ONLINE);
		
		// istanzia oggetto con servizio di registrazione al server
		ServerRegister registrationObj = new ServerRegister(PRIV_KEY, USERS_OFFLINE, USERS_ONLINE);
				
		try {
			// esporta STUB per la registrazione su porta anonima
			ServerRegisterInterface stub_registration =
				(ServerRegisterInterface) UnicastRemoteObject.exportObject(registrationObj, 0);
			
			// esporta STUB per CALLBACK sullo stato degli utenti su porta anonima
			ServerCallbackInterface stub_users =
					(ServerCallbackInterface) UnicastRemoteObject.exportObject(STUB_CALLBACK, 0);
			
			// crea REGISTRY su porta specifica
			LocateRegistry.createRegistry(PORT_REGISTRY);			
			Registry registry = LocateRegistry.getRegistry(PORT_REGISTRY);
			
			// pubblica gli STUB nel REGISTRY
			registry.rebind(RMI_REGISTER, stub_registration);
			registry.rebind(RMI_CALLBACK, stub_users);
		}
		catch(RemoteException e) {
			System.err.println("[ERRORE] impossibile abilitare i servizi RMI.");
			System.exit(-1);
		}
		System.out.println("[SERVER] SERVIZI RMI PUBBLICATI");
	}
	
	// inizializza socket in ascolto di connessioni TCP
	private void inizializza_server_tcp() {
		try {
			SELECTOR = Selector.open();
			SOCKET = ServerSocketChannel.open();
			// imposta socket in modalità non bloccante
			SOCKET.configureBlocking(false);
			// imposta socket in ascolto su porta specifica
			SOCKET.socket().bind(new InetSocketAddress(PORT_TCP));
			// associa il socket in ascolto al selettore
			SOCKET.register(SELECTOR, SelectionKey.OP_ACCEPT);
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile inzializzare server TCP.");
			System.exit(-1);
		}
		System.out.println("[SERVER] ATTESA DI CONNESSIONI TCP\n");
	}
	
	// genera indirizzo IP multicast libero
	private String nextMulticastIP() {
		
		// verifica se è disponibile l'indirizzo IP di un progetto cancellato
		if(IP_FREE.size() > 0) {
			// estrai IP dalla lista
			String ip = IP_FREE.pop();
			// aggiornameto file con lista indirizzi IP liberi
			try(FileOutputStream out = new FileOutputStream(PATH_IP + "/free_ip")){
				for(String s : IP_FREE)
					out.write((s+"\n").getBytes());
			}
			catch(IOException e) {
				System.err.println("[ERRORE] impossibile accedere a file \"free_ip\".");
				System.exit(-1);
			}
			return ip;
		}
		
		String ip = IP_NEXT[0] + "." + IP_NEXT[1] + "." + IP_NEXT[2] + "." + IP_NEXT[3];
				
		if(IP_NEXT[3] == 255) {
			IP_NEXT[3] = 0;
			if(IP_NEXT[2] == 255) {
				IP_NEXT[2] = 0;
				if(IP_NEXT[1] == 255) {
					IP_NEXT[1] = 0;
					if(IP_NEXT[0] > 239) return null;
					IP_NEXT[0]++;
				}
				else IP_NEXT[1]++;
			}
			else IP_NEXT[2]++;
		}
		else IP_NEXT[3]++;
		
		String next_ip = IP_NEXT[0] + "." + IP_NEXT[1] + "." + IP_NEXT[2] + "." + IP_NEXT[3];
		
		// aggiornameto file con prossimo indirizzo IP multicast libero
		try(FileOutputStream out = new FileOutputStream(PATH_IP + "/next_ip")){
			out.write(next_ip.getBytes());
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile accedere a file \"next_ip\".");
			System.exit(-1);
		}
		return ip;
	}
	
	// logout automatizzato per connessione TCP terminata bruscamente
	private void gestisci_disconnessione(SelectionKey key) {
		
		if(key.channel() instanceof SocketChannel) {
			SocketChannel client = (SocketChannel) key.channel();
			String attachment = (String) key.attachment();
			
			// verifica se client ha effettuato login (username allegato)
			if(!attachment.equals("")) {
				User u;
				// accesso a tabelle utenti [mutua esclusione con ServerCallback e ServerRegister]
				synchronized(USERS_ONLINE) {
					// rimuove utente da tabella con utenti connessi
					u = USERS_ONLINE.remove(attachment);
					// inserisce utente tra quelli disconnessi
					USERS_OFFLINE.put(attachment, u);
					
					// elimina STUB per CALLBACK associato all'utente
					u.setCallbackStub(null);
					// elimina password aes associata all'utente
					u.setPasswordAES(null);
					
					// effettua CALLBACK per aggionare i clients a seguito della disconnessione
					callback_cambiamento_stato_utente("offline " + attachment);
				}
				// sovrascrive username associato alla key del client con la stringa vuota
				key.attach(new String(""));
				System.out.println("[SERVER] logout: " + attachment);
			}
			
			try {System.out.println("[SERVER] - " + client.getRemoteAddress());}
			catch(IOException e) {}
		}
		else {
			System.err.println("[ERRORE] socket binding terminato.");
			System.exit(-1);
		}
		
		// eliminazione chiave
		key.cancel();
		try {key.channel().close();} catch(IOException e) {}
	}
	
	// inizializzazione connessione col client
	private void gestione_selector_acceptable(SelectionKey key) throws IOException {
		// estrazine socket TCP in ascolto dalla key
		ServerSocketChannel server = (ServerSocketChannel) key.channel();
		// acettazione della comunicazione col client
		SocketChannel client = server.accept();
		// client impostato come non bloccante
		client.configureBlocking(false);
		// associa il client al selettore per le operazioni di lettura
		SelectionKey new_key = client.register(SELECTOR, SelectionKey.OP_READ);
		// allega alla key del client una stringa vuota (sarà sostituita dallo username dopo il login)
		new_key.attach(new String(""));
		
		System.out.println("[SERVER] + " + client.getRemoteAddress());
	}
	
	// lettura messaggio dal client ed esecuzione servizio richiesto
	private void gestione_selector_readable(SelectionKey key) throws IOException {
		
		// estrazine socket TCP del client dalla key
		SocketChannel client = (SocketChannel) key.channel();
		// allocazione buffer per la lettura dei dati ricevuti dal client
		ByteBuffer buffer = ByteBuffer.allocate(SIZE_BUFFER);
		
		// lettura dati dal client (gestione eventuale disconnessione)
		if(client.read(buffer) == -1) throw new IOException();
		
		// conversione byte ricevuti in stringa
		String cript_msg = new String(buffer.array()).trim();
				
		// estrazione stringa associata al client
		String attachment = (String) key.attachment();
		
		/** gestione client connesso senza login (stringa vuota allegata alla key) **/
		/** richiesta del client codificata in RSA con chiave pubblica del server **/
		/** risposta del server in chiaro **/
		if(attachment.equals("")){
			
			// decodifica RSA della richiesta del client con chiave privata del server
			String msg = Security.rsa_decripta(PRIV_KEY, cript_msg);
			if(msg == null) throw new IOException();
			
			// estrazione argomenti della richiesta
			String[] cmd = msg.split("\\|");
			
			// blocca richieste per cui è necessario il login
			if(!cmd[0].equals("login")) {
				invia_messaggio_client(client, "è necessario effettuare il login");
				return;
			}
			// gestisci login dell'utente
			login(client, key, cmd);
			return;
		}
		
		/** gestione client che ha effettuato login (stringa con username allegata alla key) **/
		/** scambio di messaggi client-server codificati in AES **/
		
		// qui NON serve la synchronized perchè SOLO ServerMain aggiunge le entry alla HashMap USERS_ONLINE
		// (e modifica la password AES dell'istanza utente estratta) E lo fa SOLO in modo sequenziale.
		// Quindi USERS_ONLINE è attualmente in READ-ONLY e sono consentite get() concorrenti
		User u = USERS_ONLINE.get(attachment);
		String aes_key = u.getPasswordAES();
		
		// decodifica AES della richiesta del client
		String msg = Security.aes_decripta(aes_key, cript_msg);
		if(msg == null) throw new IOException();
		
		// estrazione argomenti della richiesta
		String[] cmd = msg.split("\\|");
		
		// blocca richiesta di login
		if(cmd[0].equals("login")) {
			invia_messaggio_client(client, "login già effettuato");
			return;
		}
		
		// gestione richiesta del client
		switch(cmd[0]) {
			case("logout"):
				logout(client, key, u, attachment);
				break;
			case("listprojects"):
				listProjects(client, u, attachment);
				break;
			case("createproject"):
				createProject(client, u, attachment, cmd);
				break;
			case("addmember"):
				addMember(client, u, attachment, cmd);
				break;
			case("showmembers"):
				showMembers(client, u, attachment, cmd);
				break;
			case("showcards"):
				showCards(client, u, attachment, cmd);
				break;
			case("showcard"):
				showCard(client, u, attachment, cmd);
				break;
			case("addcard"):
				addCard(client, u, attachment, cmd);
				break;
			case("movecard"):
				moveCard(client, u, attachment, cmd);
				break;
			case("getcardhistory"):
				getCardHistory(client, u, attachment, cmd);
				break;
			case("cancelproject"):
				cancelProject(client, u, attachment, cmd);
				break;
			default:
				invia_messaggio_aes_client(client, aes_key, "richiesta sconosciuta");
		}
	}
	
	
	/** CALLBACK **********************************************************************************************************/
	
	public void callback_cambiamento_stato_utente(String msg) {
		
		for(String username : USERS_ONLINE.keySet()) {
			User u = USERS_ONLINE.get(username);
			ClientCallbackInterface client = u.getCallbackStub();
			if(client == null) continue;
			
			// codifica AES del messaggio con lo stato dell'utente
			String msgAES = Security.aes_cripta(u.getPasswordAES(), msg);
			
			try {
				client.notifica_cambiamento_stato_utente(msgAES);
			}
			catch(RemoteException e) {
				// elimina STUB per CALLBACK associato all'utente
				u.setCallbackStub(null);
			}
		}
	}
	public void callback_nuova_chat_progetto(User u, String project, String chat_ip, String chat_aes_key) {
		
		ClientCallbackInterface client = u.getCallbackStub();
		if(client == null) return;
		
		// concatena dati di accesso alla chat
		String msg = project + " " + chat_ip + " " + chat_aes_key;
		// codifica dati con chiave AES della comunicazione client-server
		String msgAES = Security.aes_cripta(u.getPasswordAES(), msg);
		
		try {
			// effettua CALLBACK
			client.notifica_nuova_chat_progetto(msgAES);
		}
		catch(RemoteException e) {
			// elimina STUB per CALLBACK associato all'utente
			u.setCallbackStub(null);
		}
	}
	public void callback_chiusura_chat_progetto(User u, String project) {
		
		ClientCallbackInterface client = u.getCallbackStub();
		if(client == null) return;
		
		// codifica nome progetto con chiave AES della comunicazione client-server
		String msgAES = Security.aes_cripta(u.getPasswordAES(), project);
		
		try {
			// effettua CALLBACK
			client.notifica_chiusura_chat_progetto(msgAES);
		}
		catch(RemoteException e) {
			// elimina STUB per CALLBACK associato all'utente
			u.setCallbackStub(null);
		}
	}
	
	
	/** SERVIZI TCP OFFERTI ALL'UTENTE ************************************************************************************/
	
	private void login(SocketChannel client, SelectionKey key, String[] cmd) throws IOException {
		
		// verifica argomenti necessari per il login
		if(cmd.length != 4) {
			invia_messaggio_client(client, "utilizzare sintassi: \"login <username> <password> <aes_key>\"");
			return;
		}
		// verifica validità del nome utente
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_client(client, "username non valido");
			return;
		}
		// verifica validità della password
		if(!Util.checkValidPassword(cmd[2])) {
			invia_messaggio_client(client, "password non valida");
			return;
		}
		// verifica validità della chiave AES
		if(Security.aes_cripta(cmd[3], "msg") == null) {
			invia_messaggio_client(client, "chiave AES non valida");
			return;
		}
		
		String err = null;
		User u = null;
		// ricerca utente tra i registrati [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			// verifica se utente è online
			if(USERS_ONLINE.containsKey(cmd[1])) {
				err = "utente risulta già connesso";
			}
			// verifica se utente è registrato
			else if((u = USERS_OFFLINE.get(cmd[1])) == null) {
				err = "utente inesistente";
			}
			// verifica correttezza password di accesso
			else if(!Security.sha256(cmd[2]).equals(u.getPasswordHash())) {
				err = "password errata";
			}
			// imposta utente come connesso
			else {
				// rimuove l'utente dalla tabella degli utenti disconnessi
				USERS_OFFLINE.remove(cmd[1]);
				// aggiunge l'utente alla tabella degli utenti connessi
				USERS_ONLINE.put(cmd[1], u);
				// associa all'utente la chiave AES per le future comunicazioni col server
				u.setPasswordAES(cmd[3]);
				
				// effettua CALLBACK per aggionare i clients a seguito del login
				callback_cambiamento_stato_utente("online " + cmd[1]);
			}
		}
		// invia eventuale messaggio di errore al client
		if(err != null) {
			invia_messaggio_client(client, err);
			return;
		}
		
		// associa username alla key del client
		key.attach(cmd[1]);
		
		System.out.println("[SERVER] login: " + cmd[1]);
		invia_messaggio_client(client, "accesso eseguito");
	}
	private void logout(SocketChannel client, SelectionKey key, User u, String username) throws IOException {
		
		String aes_key;
		
		// accesso a tabelle utenti [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			// rimuove utente da tabella con utenti connessi
			USERS_ONLINE.remove(username);
			// inserisce utente tra quelli offline
			USERS_OFFLINE.put(username, u);
			
			// elimina STUB per CALLBACK associato all'utente
			u.setCallbackStub(null);
			// recupera password AES per l'ultima comunicazione col client
			aes_key = u.getPasswordAES();
			// elimina password aes associata all'utente
			u.setPasswordAES(null);
			
			// effettua CALLBACK per aggionare i clients a seguito della disconnessione
			callback_cambiamento_stato_utente("offline " + username);
		}
		
		// sovrascrive username associato alla key del client con la stringa vuota
		key.attach(new String(""));
		
		invia_messaggio_aes_client(client, aes_key, "logout effettuato");
		System.out.println("[SERVER] logout: " + username);
	}
	private void listProjects(SocketChannel client, User u, String username) throws IOException {
		
		// estrazione nomi dei progetti di cui l'utente è membro
		ArrayList<String> projects = u.getProjects();
		if(projects.size() == 0) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "non sei membro di alcun progetto");
			return;
		}
		
		// creazione messaggio con lista dei progetti
		String msg = "PROGETTI: ";
		for(int i=0; i<projects.size()-1; i++)
			msg += projects.get(i) + ", ";
		msg += projects.get(projects.size()-1);
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), msg);
	}
	private void createProject(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale di argomenti
		if(cmd.length != 2) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"createproject <project_name>\"");
			return;
		}
		// verifica se nome progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se nome progetto è disponibile
		if(PROJECTS.containsKey(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "progetto già esistente");
			return;
		}
		
		// generazione indirizzo IP multicast libero per la chat del progetto
		String chat_ip = nextMulticastIP();
		if(chat_ip == null) {
			System.err.println("[ERRORE] indirizzi IP multicast terminati.");
			invia_messaggio_aes_client(client, u.getPasswordAES(), "raggiunto limite massimo di progetti");
			return;
		}
		// generazione chiave AES per la chat del progetto
		String chat_aes_key = Security.aes_genera_chiave();
		if(chat_aes_key == null) {
			System.err.println("[SERVER][ERRORE] impossibile generare chiave AES.");
			System.exit(-1);
		}
		// creazione istanza del nuovo progetto
		Project p = new Project(chat_ip, chat_aes_key);
		// utente aggiunto nella lista membri del progetto
		p.addMember(username);
		
		String path = PATH_PROJECTS + "/" + cmd[1];
		
		// creazione directory del progetto
		if(new File(path).mkdir() == false) {
			System.err.println("[ERRORE] impossibile creare directory per il progetto.");
			System.exit(-1);
		}
		// creazione file con lista membri del progetto
		try(ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path + "/_members"))) {
			out.writeObject(p.getArrayMembers());
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile creare file con membri del progetto.");
			System.exit(-1);
		}
		
		String chat_data = chat_ip + "\n" + chat_aes_key;
		
		// creazione file con dati della chat del progetto
		try(FileOutputStream out = new FileOutputStream(path + "/_chat")) {
			out.write(chat_data.getBytes());
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile creare file con dati chat del progetto.");
			System.exit(-1);
		}
		
		// nome del progetto associato all'utente
		u.addProject(cmd[1]);
		
		// [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			// istanza del progetto aggiunta alla tabella dei progetti
			PROJECTS.put(cmd[1], p);
			// CALLBACK per comunicare dati di accesso alla chat del progetto
			callback_nuova_chat_progetto(u, cmd[1], chat_ip, chat_aes_key);
		}
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), "progetto creato");
		System.out.println("[SERVER] new [project:" + cmd[1] + "] [by:" + username + "]");
	}
	private void addMember(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale di argomenti
		if(cmd.length != 3) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"addmember <project_name> <username>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se il nome utente è valido
		if(!Util.checkValidName(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "username non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi aggiungere utenti solo ai progetti di cui sei membro");
			return;
		}
		if(username.equals(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "sei già membro del progetto");
			return;
		}
		
		User new_member;
		// estrazione utente dalle tabelle [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			if((new_member = USERS_OFFLINE.get(cmd[2])) == null)
				new_member = USERS_ONLINE.get(cmd[2]);
		}
		// verifica se esiste l'utente da aggiungere al progetto
		if(new_member == null) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utente inesistente");
			return;
		}
		// verifica se l'utente da aggiungere è già membro del progetto
		if(new_member.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utente già membro del progetto");
			return;
		}
		
		String path = PATH_PROJECTS + "/" + cmd[1];
		
		// aggiorna file con lista membri del progetto
		try {
			// lettura da file della lista membri del progetto
			ObjectInputStream in = new ObjectInputStream(new FileInputStream(path + "/_members"));
			String[] list = (String[]) in.readObject();
			in.close();
			
			// creazione nuova lista membri
			String[] new_list = new String[list.length + 1];
			int i;
			for(i=0; i<list.length; i++)
				new_list[i] = list[i];
			
			// nuovo membro aggiunto alla lista
			new_list[i] = cmd[2];
			
			// scrittura su file dell'array aggiornato
			ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path + "/_members"));
			out.writeObject(new_list);
			out.close();
		}
		catch(Exception e) {
			System.err.println("[ERRORE] impossibile modificare file con membri del progetto.");
			System.exit(-1);
		}
		
		// progetto viene associato all'utente che è diventato membro
		new_member.addProject(cmd[1]);
		
		Project p = PROJECTS.get(cmd[1]);
		// nuovo membro aggiunto al progetto
		p.addMember(cmd[2]);	
		
		// [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			// CALLBACK per comunicare dati di accesso alla chat del progetto
			callback_nuova_chat_progetto(new_member, cmd[1], p.getChatIP(), p.getChatAESKey());	
		}
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), "utente aggiunto al progetto");
		System.out.println("[SERVER] new [member:" + cmd[2] + "] [project:" + cmd[1] + "] [by:" + username + "]");
	}
	private void showMembers(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale di argomenti
		if(cmd.length != 2) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"showmembers <project_name>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi visualizzare i membri solo dei progetti di cui sei membro");
			return;
		}
		
		// estrazione array con username dei membri del progetto
		String[] members = PROJECTS.get(cmd[1]).getArrayMembers();
		
		// creazione messaggio con lista dei membri
		String msg = "MEMBRI: ";
		int i;
		for(i=0; i<members.length-1; i++)
			msg += members[i] + ", ";
		msg += members[i];
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), msg);
	}
	private void showCards(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"showcards <project_name>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi visualizzare le cards solo dei progetti di cui sei membro");
			return;
		}
		
		// estrazione lista di nomi delle cards nel progetto
		ArrayList<String> cards = PROJECTS.get(cmd[1]).getCards();
		if(cards.size() == 0) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "il progetto non contiene cards");
			return;
		}
		
		// creazione messaggio con lista di cards
		String msg = "CARDS: ";
		for(int i=0; i<cards.size()-1; i++)
			msg += cards.get(i) + ", ";
		msg += cards.get(cards.size()-1);
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), msg);
	}
	private void showCard(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 3) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"showcard <project_name> <card_name>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome della card non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi visualizzare le cards solo dei progetti di cui sei membro");
			return;
		}
		
		// estrazione card dal progetto
		Card c = PROJECTS.get(cmd[1]).getCardByName(cmd[2]);
		if(c == null) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "card non presente nel progetto");
			return;
		}
		
		// creazione messaggio con stato e descrizione della card
		String msg = "CARD: " + cmd[2] + "\n         STATO: " + c.getActualState() + "\n         DESCRIZIONE: " + c.getDesc();
		invia_messaggio_aes_client(client, u.getPasswordAES(), msg);
	}
	private void addCard(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 4) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"addcard <project_name> <card_name> <desc>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome della card non valido");
			return;
		}
		// verifica se la decrizione della card è valida
		if(!Util.checkValidCardDesc(cmd[3])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "descrizione della card non valida");
			return;
		}
		// verifica se utente è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi aggiungere card solo ai progetti di cui sei membro");
			return;
		}
		
		// estrazione istanza del progetto
		Project p = PROJECTS.get(cmd[1]);
		
		// verifica se il nome della card è già utilizzato nel progetto
		if(p.containsCard(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "card già presente nel progetto");
			return;
		}
		
		// creazione nuova istanza card
		Card c = new Card(cmd[3]);
		// card aggiunta all'istanza del progetto
		p.addCard(cmd[2], c);
		
		String path = PATH_PROJECTS + "/" + cmd[1] + "/" + cmd[2];
		
		// creazione file della card nella directory del progetto
		try(ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path))) {
			// scrittura su file della card serializzata
			out.writeObject(c);
		}
		catch(Exception e) {
			System.err.println("[ERRORE] impossibile aggiornare file della card.");
			System.exit(-1);
		}
		
		// creazione messaggio inviato dal server sulla chat del progetto
		String msg = String.format("<SERVER> CREATA [card:%s] [by:%s]", cmd[2], username);
		// invio del messaggio sulla chat del progetto
		p.sendChatMsg(msg);
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), "card aggiunta al progetto");
		System.out.println("[SERVER] new [card:" + cmd[2] + "] [project:" + cmd[1] + "] [by:" + username + "]");
	}
	private void moveCard(SocketChannel client, User u, String username, String[] cmd) throws IOException {
				
		// verifica totale argomenti
		if(cmd.length != 5) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"movecard <project_name> <card_name> <start_list> <end_list>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome della card non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi visualizzare solo le cards dei progetti di cui sei membro");
			return;
		}
		
		// estrazione istanza del progetto
		Project p = PROJECTS.get(cmd[1]);
		// estrazione istanza della card nel progetto
		Card c = p.getCardByName(cmd[2]);
		
		// verifica presenza della card nel progetto
		if(c == null) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "card non presente nel progetto");
			return;
		}
		// verifica validità delle liste iniziale e finale
		if(!Util.isValidState(cmd[3])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "lista di partenza non valida");
			return;
		}
		if(!Util.isValidState(cmd[4])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "lista di arrivo non valida");
			return;
		}
		// verifica se lo spostamento della card è valido
		if(!Util.isValidMove(cmd[3], cmd[4])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "spostamento non valido");
			return;
		}
		// verifica presenza della card nella lista iniziale
		if(!p.listContainsCard(cmd[3], cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "card non presente nella lista iniziale");
			return;
		}
		
		// sposta card da lista inziale a lista finale nell'istanza del progetto
		p.moveCard(cmd[2], cmd[3], cmd[4]);
		// aggiornamento cronologia spostamenti dell'istanza della card
		c.updateHistory(cmd[4]);
		
		String path = PATH_PROJECTS + "/" + cmd[1] + "/" + cmd[2];
		
		// aggiornamento file della card nella directory del progetto
		try(ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream(path))) {
			// sovrascrittura file della card con nuova serializzazione
			out.writeObject(c);
		}
		catch(Exception e) {
			System.err.println("[ERRORE] impossibile creare file della card.");
			System.exit(-1);
		}
				
		String out = String.format("[card:%s] [project:%s] [from:%s] [to:%s] [by:%s]",cmd[2],cmd[1],cmd[3],cmd[4],username);
		// creazione messaggio inviato dal server sulla chat del progetto
		String msg = String.format("<SERVER> SPOSTATA " + out);
		// invio del messaggio sulla chat del progetto
		p.sendChatMsg(msg);
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), "spostamento effettuato");
		System.out.println("[SERVER] moved " + out);
	}
	private void getCardHistory(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 3) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"getcardhistory <project_name> <card_name>\"");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome della card non valido");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi visualizzare le cards solo dei progetti di cui sei membro");
			return;
		}
		
		// estrazione card dal progetto
		Card c = PROJECTS.get(cmd[1]).getCardByName(cmd[2]);
		if(c == null) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "card non presente nel progetto");
			return;
		}
		
		// creazione messaggio con cronologia della card
		String msg = "HISTORY: " + c.getHistory();
		invia_messaggio_aes_client(client, u.getPasswordAES(), msg);
	}
	private void cancelProject(SocketChannel client, User u, String username, String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "utilizzare sintassi: \"cancelproject <project_name>\"");
			return;
		}
		// verifica se nome progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "nome del progetto non valido");
			return;
		}
		
		// estrai istanza del progetto da tabella
		Project p = PROJECTS.get(cmd[1]);
		
		// verifica esistenza del progetto
		if(p == null) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "progetto inesistente");
			return;
		}
		// verifica se client è membro del progetto
		if(!u.isMember(cmd[1])) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "puoi cancellare solo progetti di cui sei membro");
			return;
		}
		// verifica se tutte le cards sono il lista DONE
		if(!p.isDeletable()) {
			invia_messaggio_aes_client(client, u.getPasswordAES(), "tutte le cards devono essere in stato di DONE");
			return;
		}
		
		// estrazione array con username dei membri del progetto
		String[] members = p.getArrayMembers();
		
		// accesso alle tabelle utenti [mutua esclusione con ServerCallback e ServerRegister]
		synchronized(USERS_ONLINE) {
			for(String s : members) {
				// estrai istanza utente dalle tabelle utenti
				User member = USERS_OFFLINE.get(s);
				if(member == null) member = USERS_ONLINE.get(s);
				// rimuovi dall'istanza dell'utente la partecipazione al progetto
				member.removeProject(cmd[1]);
				
				// CALLBACK per comunicare chiusura della chat del progetto
				callback_chiusura_chat_progetto(member, cmd[1]);
				
				// eliminazione istanza del progetto dalla tabella
				PROJECTS.remove(cmd[1]);
			}
		}
		
		String path = PATH_PROJECTS + "/" + cmd[1];
		
		// apertura directory del progetto
		File dir = new File(path);
		if(!dir.exists() || !dir.isDirectory()) {
			System.err.println("[ERRORE] directory di progetto inesistente.");
			System.exit(-1);
		}
		// eliminazione file nella directory del progetto
		for(String file : dir.list())
			new File(path + "/" + file).delete();
		// eliminazione directory del progetto
		dir.delete();
		
		// recupero indirizzo IP della chat di progetto
		IP_FREE.push(p.getChatIP());
		
		// scrittura stringa con lista di indirizzi IP liberi
		try(FileOutputStream out = new FileOutputStream(PATH_IP + "/free_ip")){
			for(String s : IP_FREE)
				out.write((s + "\n").getBytes());
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile accedere a file \"free_ip\".");
			System.exit(-1);
		}
		
		invia_messaggio_aes_client(client, u.getPasswordAES(), "progetto cancellato");
		System.out.println("[SERVER] deleted [project:" + cmd[1] + "] [by:" + username + "]");
	}
	
	
}
