import java.io.Console;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.rmi.RemoteException;
import java.rmi.NotBoundException;
import java.rmi.registry.*;
import java.rmi.server.UnicastRemoteObject;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.LinkedList;


public class ClientMain {
	
	/** COSTANTI STATICHE *************************************************************************************************/
	
	public final static String		PATH_HOME			=	"./client/home";
	public final static String		PATH_CERTIFICATE	=	PATH_HOME + "/_certificate";
	public final static String		SERVER_NAME			=	"localhost";
	public final static String		RMI_REGISTER		=	"REGISTER";
	public final static String		RMI_CALLBACK		=	"CALLBACK";
	public final static int			PORT_REGISTRY		=	54000;
	public final static int			PORT_TCP			=	55555;
	public final static int			PORT_MULTICAST		=	56000;
	public final static int			SIZE_BUFFER			=	1024;
	
	
	/** VARIABILI LOCALI **************************************************************************************************/
	
	// chiave pubblica RSA del server
	private final PublicKey CERTIFICATO;
	
	// socket per comunicazione TCP client-server
	private final SocketChannel SOCKET;
	
	// lista di comandi disponibili
	private final ArrayList<String> MENU;
	
	// liste con username degli utenti registrati
	private final LinkedList<String> USERS_OFFLINE;
	private final LinkedList<String> USERS_ONLINE;
	
	// tabella che associa ai nomi dei progetti i thread in ascolto dei messaggi delle corrispettive chat	
	private final HashMap<String, ClientChat> CHAT_READERS;
	
	// username dell'utente che ha effettuato il login (null altrimenti)
	private String USERNAME;
	// chiave AES per la comunicazione col server dopo aver effettuato il login (null altrimenti)
	private String AES_KEY;
	
	// STUB offerto dal server per la registrazione di un nuovo utente
	private ServerRegisterInterface STUB_SERVER_REGISTER;
	// STUB offerto dal server per registrarsi a CALLBACK di aggiornameto sullo stato di utenti e progetti
	private ServerCallbackInterface STUB_SERVER_CALLBACK;
	// STUB consegnato al server per inviare CALLBACK di aggiornamento
	private ClientCallbackInterface STUB_CLIENT_CALLBACK;
	
	// oggetto pubblicato dal client per ricevere CALLBACK del server (null se client non loggato)
	private ClientCallbackInterface CLIENT_CALLBACK_OBJ;
	// true se utente si è registrato al servizio CALLBACK del server
	private boolean CALLBACK_REGISTRATION;
	
	
	/** COSTRUTTORE *******************************************************************************************************/
	
	public ClientMain() {
		this.CERTIFICATO			=	carica_certificato();
		this.SOCKET					=	connetti_client();
		this.MENU					=	genera_menu();
		this.USERS_OFFLINE			=	new LinkedList<String>();
		this.USERS_ONLINE			=	new LinkedList<String>();
		this.CHAT_READERS			=	new HashMap<String, ClientChat>();
		this.USERNAME				=	null;
		this.AES_KEY				=	null;
		this.CLIENT_CALLBACK_OBJ	=	null;
		this.CALLBACK_REGISTRATION	=	false;
	}
	
	
	/** MAIN **************************************************************************************************************/
	public static void main(String[] args) {
		ClientMain client = new ClientMain();
		client.START();
	}
	
	
	/** METODI STATICI ****************************************************************************************************/
	
	private static PublicKey carica_certificato() {
		// lettura da file della chiave pubblica RSA del server
		PublicKey pub_key = Security.rsa_importa_pub_key(PATH_CERTIFICATE);
		if(pub_key == null) {
			System.err.println("[ERRORE] certificato non trovato o non valido.");
			System.exit(-1);
		}
		return pub_key;
	}
	
	private static SocketChannel connetti_client() {
		SocketChannel socket = null;
		try {
			// creazione socket TCP del client
			socket = SocketChannel.open();
			// socket tenta di connettersi al server
			socket.connect(new InetSocketAddress(SERVER_NAME, PORT_TCP));			
		}
		catch(UnknownHostException e) {
			System.err.println("[ERRORE] IP del server non determinabile.");
			System.exit(-1);
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile connettersi al server.");
			System.exit(-1);
		}
		System.out.println("[CLIENT] CONNESSO AL SERVER");
		return socket;
	}
	
	private static ArrayList<String> genera_menu() {
		ArrayList<String> menu = new ArrayList<String>(19);
		menu.add("register");
		menu.add("login");
		menu.add("logout");
		menu.add("listprojects");
		menu.add("createproject <project_name>");
		menu.add("addmember <project_name> <username>");
		menu.add("showmembers <project_name>");
		menu.add("showcards <project_name>");
		menu.add("showcard <project_name> <card_name>");
		menu.add("addcard <project_name> <card_name> <desc>");
		menu.add("movecard <project_name> <card_name> <list_start> <list_end>");
		menu.add("getcardhistory <project_name> <card_name>");
		menu.add("cancelproject <project_name>");
		menu.add("listusers");
		menu.add("listonlineusers");
		menu.add("readchat <project_name>");
		menu.add("sendchatmsg <project_name> <msg>");
		menu.add("exit");
		menu.add("info");
		return menu;
	}
	
	private static String[] input_dati_utente() {
		
		Console console = System.console();
		if (console == null) {
			System.err.println("[ERRORE] impossibile accedere alla console.");
			return null;
		}
		// crea coppia di stringhe per username e password
		String[] data = new String[2];
		
		// acquisizione username
		System.out.print("Username: ");
		data[0] = (new String(console.readLine())).trim();
		if(data[0].equals("")) {
			System.out.println("[X] operazione annullata.");
			return null;
		}
		// verifica validità username
		if(!Util.checkValidName(data[0])) {
			System.err.println("[ERRORE] username non valido.");
			return null;
		}
		
		// acquisizione password NON in chiaro
		System.out.print("Password: ");
		data[1] = (new String(console.readPassword())).trim();
		if(data[1].equals("")) {
			System.out.println("[X] operazione annullata.");
			return null;
		}
		// verifica validità password
		if(!Util.checkValidPassword(data[1])) {
			System.err.println("[ERRORE] password non valida.");
			return null;
		}
		
		return data;
	}
	
	
	/** METODI LOCALI *****************************************************************************************************/
	
	public void START() {
		
		inizializza_servizi_rmi();
		
		System.out.println("[CLIENT] Digita <menu> per l'elenco comandi");
		
		Scanner input = new Scanner(System.in);
		while(true) {
			System.out.print(">>> ");
			// lettura comando da tastiera
			String[] cmd = input.nextLine().trim().split(" ");
			if(cmd[0].equals("")) continue;
			if(cmd[0].equals("exit")) break; /** terminazione improvvisa **/
			
			switch(cmd[0]) {
				case("menu"):
					for(String s : MENU)
						System.out.println("  - " + s);
					continue;
				case("info"):
					info();
					continue;
				case("register"):
					gestione_register();
					continue;
			}
			if((USERNAME == null) && (!cmd[0].equals("login"))) {
				System.err.println("[ERRORE] effettuare il login.");
				continue;
			}
			try {
				switch(cmd[0]) {
					case("login"):
						gestione_login();
						break;
					case("logout"):
						gestione_logout();
						break;
					case("listprojects"):
						gestione_listProjects();
						break;
					case("createproject"):
						gestione_createProject(cmd);
						break;
					case("addmember"):
						gestione_addMember(cmd);
						break;
					case("showmembers"):
						gestione_showMembers(cmd);
						break;
					case("showcards"):
						gestione_showCards(cmd);
						break;
					case("showcard"):
						gestione_showCard(cmd);
						break;
					case("addcard"):
						gestione_addCard(cmd);
						break;
					case("movecard"):
						gestione_moveCard(cmd);
						break;
					case("getcardhistory"):
						gestione_getCardHistory(cmd);
						break;
					case("cancelproject"):
						gestione_cancelProject(cmd);
						break;
					case("listusers"):
						gestione_listUsers();
						break;
					case("listonlineusers"):
						gestione_listOnlineUsers();
						break;
					case("readchat"):
						gestione_readChat(cmd);
						break;
					case("sendchatmsg"):
						gestione_sendChatMsg(cmd);
						break;
					default:
						System.err.println("[ERRORE] comando non valido.");
				}
			}
			catch(IOException e) {
				System.err.println("[ERRORE] connessione interrotta.");
				break;
			}
		}
		input.close();
		
		// disconnessione client dal server TCP
		try {SOCKET.close();} catch(Exception e) {}
		System.exit(0);
	}
	
	public void inizializza_servizi_rmi() {
		try {
			// estrai REGISTRY con servizi messi a disposizione dal server
			Registry registry = LocateRegistry.getRegistry(PORT_REGISTRY);
			
			// etrai dal REGISTRY l'oggetto remoto col servizio di registrazione
			STUB_SERVER_REGISTER = (ServerRegisterInterface) registry.lookup(RMI_REGISTER);
			
			// etrai dal REGISTRY l'oggetto remoto col servizio di iscrizione CALLBACK
			STUB_SERVER_CALLBACK = (ServerCallbackInterface) registry.lookup(RMI_CALLBACK);
		}
		catch(NotBoundException | IOException e) {
			System.err.println("[ERRORE] impossibile accedere a servizi RMI.");
			System.exit(-1);
		}
	}
	
	private String invia_messaggio_rsa(String msg) throws IOException {
		
		// codifica del messaggio con chiave pubblica RSA del server (certificato)
		String msgRSA = Security.rsa_cripta(CERTIFICATO, msg);
		if(msgRSA == null) {
			System.err.println("[ERRORE] impossibile effettuare la codifica RSA degli argomenti");
			System.exit(-1);
		}
		
		// allocazione buffer contenente il messaggio
		ByteBuffer buffer = ByteBuffer.wrap(msgRSA.getBytes());
		// invio del messaggio al server TCP
		SOCKET.write(buffer);
		
		// allocazione buffer per la ricezione della risposta del server
		buffer = ByteBuffer.allocate(SIZE_BUFFER);
		// ricezione risposta del server
		SOCKET.read(buffer);
		// conversione byte ricevuti in stringa (non criptata)
		String risp = new String(buffer.array(),Security.CHAR_SET).trim();
		return risp;
	}
	
	private String invia_messaggio_aes(String msg) throws IOException {
		
		// codifica messaggio con chiave AES
		String msgAES = Security.aes_cripta(AES_KEY, msg);
		if(msgAES == null) {
			System.err.println("[ERRORE] impossibile effettuare la codifica AES degli argomenti");
			System.exit(-1);
		}
		
		// allocazione buffer contenente il messaggio
		ByteBuffer buffer = ByteBuffer.wrap(msgAES.getBytes());
		// invio del messaggio al server TCP
		SOCKET.write(buffer);
		
		// allocazione buffer per la ricezione della risposta del server
		buffer = ByteBuffer.allocate(SIZE_BUFFER);
		// ricezione risposta del server
		SOCKET.read(buffer);
		// conversione byte ricevuti in stringa
		String rispAES = new String(buffer.array()).trim();
		
		// decodifica AES della risposta
		String risp = Security.aes_decripta(AES_KEY, rispAES);
		if(risp == null) {
			System.err.println("[ERRORE] impossibile effettuare la decodifica AES della risposta");
			System.exit(-1);
		}
		
		return risp;
	}
	
	private void info() {
		System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
		try {
			System.out.println("[Server] " + SOCKET.getRemoteAddress().toString().split("/")[1]);
			System.out.println("[Client] " + SOCKET.getLocalAddress().toString().split("/")[1]);
		} catch(IOException e) {}
		
		System.out.print("[Codifica attuale] ");
		if(AES_KEY == null) {
			System.out.println("RSA");
		}
		else {
			System.out.println("AES");
			System.out.println("[Chiave accordata] " + AES_KEY);
			System.out.println("[Username] " + USERNAME);
			synchronized(USERS_ONLINE) {
				System.out.print("[#Utenti] " + (USERS_ONLINE.size() + USERS_OFFLINE.size()));
				System.out.println(" (di cui " + USERS_ONLINE.size() + " online)");
			}
			synchronized(CHAT_READERS) {
				System.out.println("[#ClientChat] " + CHAT_READERS.size());
				if(CHAT_READERS.size() > 0) {
					System.out.println("[Lista progetti]");
					for(String p : CHAT_READERS.keySet()) {
						System.out.println("  > " + p);
						ClientChat th = CHAT_READERS.get(p);
						System.out.println("    . ip:       " + th.getChatIP());
						System.out.println("    . aes_key:  " + th.getChatAESKey());
					}
				}
			}
		}
		System.out.println("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+");
	}
	
	
	/** SERVIZI OFFERTI DAL SERVER ****************************************************************************************/
	
	private void gestione_register() {
		
		// acquisizione username e password utente
		String[] data = input_dati_utente();
		if(data == null) return;
		
		// codifica argomenti con chiave pubblica RSA del server (certificato)
		String usernameRSA = Security.rsa_cripta(CERTIFICATO, data[0]);
		String passwordRSA = Security.rsa_cripta(CERTIFICATO, data[1]);
		if(usernameRSA == null || passwordRSA == null) {
			System.err.println("[ERRORE] impossibile effettuare la codifica RSA degli argomenti.");
			System.exit(-1);
		}
		
		try {
			// utilizza servizio remoto di registrazione
			String esito = STUB_SERVER_REGISTER.register(usernameRSA, passwordRSA);
			System.out.println(esito);
		}
		catch(RemoteException e) {
			System.err.println("[ERRORE] impossibile individuare o utilizzare il servizio RMI di registrazione.");
			System.exit(-1);
		}
	}	
	private void gestione_login() throws IOException {
		
		if(USERNAME != null) {
			System.err.println("[ERRORE] login già effettuato.");
			return;
		}
		// acquisizione username e password utente
		String[] data = input_dati_utente();
		if(data == null) return;
		
		// genera password aes per successive comunicazione col server
		String new_aes_key = Security.aes_genera_chiave();
		
		// crea messaggio concatenando gli argomenti
		// viene inserita la chiave AES per le future comunicazioni col server
		String msg = "login|" + data[0] + "|" + data[1] + "|" + new_aes_key;
		
		// messaggio inviato al server
		String risp = invia_messaggio_rsa(msg);
		System.out.println(risp);
		if(!risp.contains("accesso eseguito")) return;
		
		/** ACCESSO ESEGUITO **/
		
		// memorizza username dell'utente loggato
		USERNAME = data[0];
		// memorizza chiave AES per successive comunicazioni
		AES_KEY = new_aes_key;
		
		// istanzia oggetto utilizzato dal server per CALLBACK sul cambiamento di stato utente
		CLIENT_CALLBACK_OBJ = new ClientCallback(AES_KEY, CHAT_READERS, USERS_OFFLINE, USERS_ONLINE);
		try {
			// pubblica oggetto per CALLBACK
			STUB_CLIENT_CALLBACK = (ClientCallbackInterface) UnicastRemoteObject.exportObject(CLIENT_CALLBACK_OBJ, 0);
			}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile pubblicare oggetto RMI.");
			System.exit(-1);
		}
		
		// codifica dati utente con chiave pubblica del server
		String dataRSA = Security.rsa_cripta(CERTIFICATO, data[0] + " " + data[1]);
				
		// client si registra per CALLBACK (aggiornamento stato utenti e progetti)
		risp = STUB_SERVER_CALLBACK.registrazione_callback(STUB_CLIENT_CALLBACK, dataRSA);
		
		// suddivisione risposta in esito e lista utenti registrati
		String data_risp[] = risp.split("\n");
		System.out.println(data_risp[0]);
		if(!data_risp[0].startsWith("[RMI:CALLBACK] registrazione effettuata")) return;
		
		/** REGISTRAZIONE RMI CALLBACK EFFETTUATA **/
		
		CALLBACK_REGISTRATION = true;
		
		// decodifica AES della lista utenti
		msg = Security.aes_decripta(AES_KEY, data_risp[1]);
		if(msg == null) return;
		
		// estrazione username degli utenti registrati
		String[] users = msg.split("\n");
		
		boolean offline = true;
		// memorizzazione username degli utenti registrati in liste
		synchronized(USERS_ONLINE) {
			for(String user : users) {
				// ignora utenti aggiornati più recentemente da CALLBACK
				if(USERS_ONLINE.contains(user)) continue;
				if(USERS_OFFLINE.contains(user)) continue;
				
				// ricevuti prima utenti offline (quelli online sono dopo il punto)
				if(offline) {
					if(user.equals(".")) offline = false;
					else USERS_OFFLINE.add(user);
				}
				else USERS_ONLINE.add(user);
			}
		}
	}
	private void gestione_logout() throws IOException {
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes("logout");
		System.out.println(risp);
		
		// termina ClientChat Threads
		synchronized(CHAT_READERS) {
			for(String s : CHAT_READERS.keySet()) {
				ClientChat th = CHAT_READERS.get(s);
				th.interrupt();
			}
			CHAT_READERS.clear();
		}
		
		// rimozione oggetto pubblicato per ricevere CALLBACK
		UnicastRemoteObject.unexportObject(CLIENT_CALLBACK_OBJ, true);
		CLIENT_CALLBACK_OBJ = null;
		
		USERNAME = null;
		AES_KEY = null;
		CALLBACK_REGISTRATION = false;
	}
	private void gestione_listProjects() throws IOException {
		// messaggio inviato al server
		String risp = invia_messaggio_aes("listprojects");
		System.out.println(risp);
	}
	private void gestione_createProject(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(4) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_addMember(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 3) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(5) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		// verifica se lo username è valido
		if(!Util.checkValidName(cmd[2])) {
			System.err.println("[ERRORE] username non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1] + "|" + cmd[2];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_showMembers(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(6) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_showCards(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(7) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_showCard(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 3) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(8) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			System.err.println("[ERRORE] nome della card non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1] + "|" + cmd[2];

		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_addCard(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length < 4) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(9) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			System.err.println("[ERRORE] nome della card non valido.");
			return;
		}
		
		String desc = "";
		for(int i=3; i<cmd.length; i++)
			desc += cmd[i] + " ";
		desc = desc.trim();
		
		// verifica se la descrizione della card è valida
		if(!Util.checkValidCardDesc(desc)) {
			System.err.println("[ERRORE] descrizione della card non valida.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1] + "|" + cmd[2] + "|" + desc;
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_moveCard(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 5) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(10) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			System.err.println("[ERRORE] nome della card non valido.");
			return;
		}
		// verifica se i nomi delle liste sono validi
		if(!Util.checkValidName(cmd[3])) {
			System.err.println("[ERRORE] lista di partenza non valida." + cmd[3]);
			return;
		}
		if(!Util.checkValidName(cmd[4])) {
			System.err.println("[ERRORE] lista di arrivo non valida.");
			return;
		}
		// verifica se lo spostamento della card è valido
		if(!Util.isValidMove(cmd[3],cmd[4])) {
			System.err.println("[ERRORE] spostamento non valido");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1] + "|" + cmd[2] + "|" + cmd[3] + "|" + cmd[4];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_getCardHistory(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 3) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(11) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		// verifica se il nome della card è valido
		if(!Util.checkValidName(cmd[2])) {
			System.err.println("[ERRORE] nome della card non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1] + "|" + cmd[2];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_cancelProject(String[] cmd) throws IOException {
		
		// verifica totale argomenti
		if(cmd.length != 2) {
			System.err.println("[ERRORE] utilizzare sintassi: \"" + MENU.get(12) + "\".");
			return;
		}
		// verifica se il nome del progetto è valido
		if(!Util.checkValidName(cmd[1])) {
			System.err.println("[ERRORE] nome del progetto non valido.");
			return;
		}
		
		// crea messaggio concatenando gli argomenti
		String msg = cmd[0] + "|" + cmd[1];
		
		// messaggio inviato al server
		String risp = invia_messaggio_aes(msg);
		System.out.println(risp);
	}
	private void gestione_listUsers() {
		
		// verifica registrazione a servizio RMI per CALLBACK
		if(!CALLBACK_REGISTRATION) {
			System.err.println("[ERRORE] effettuare registrazione a servizio RMI per CALLBACK");
			return;
		}
		
		synchronized(USERS_ONLINE) {
			for(String user : USERS_OFFLINE)
				System.out.println("[OFFLINE] " + user);
			for(String user : USERS_ONLINE)
				System.out.println("[ONLINE] " + user);
		}
	}
	private void gestione_listOnlineUsers() {
		
		// verifica registrazione a servizio RMI per CALLBACK
		if(!CALLBACK_REGISTRATION) {
			System.err.println("[ERRORE] effettuare registrazione a servizio RMI per CALLBACK");
			return;
		}
		
		synchronized(USERS_ONLINE) {
			for(String user : USERS_ONLINE)
				System.out.println("[ONLINE] " + user);
		}
	}
	private void gestione_readChat(String[] cmd) {
		
		// verifica registrazione a servizio RMI per CALLBACK
		if(!CALLBACK_REGISTRATION) {
			System.err.println("[ERRORE] effettuare registrazione a servizio RMI per CALLBACK");
			return;
		}
		// verifica totale argomenti
		if(cmd.length != 2) {
			System.err.println("[ERRORE] utilizzare sintassi: \"readchat <project_name>\".");
			return;
		}
		
		ClientChat th;
		// recupera gestore chat multicast associato al progetto
		synchronized(CHAT_READERS) {
			th = CHAT_READERS.get(cmd[1]);
		}
		if(th == null) {
			System.err.println("[ERRORE] puoi leggere solo le chat dei progetti di cui sei membro.");
			return;
		}
		
		// recupera array con messaggi non visualizzati
		String[] new_messages = th.getNewMessages();
		
		// visualizza messaggi
		for(String msg : new_messages)
			System.out.println("[CHAT] " + msg);
		
		if(new_messages.length == 0)
			System.out.println("[CHAT] non ci sono nuovi messaggi.");
	}
	private void gestione_sendChatMsg(String[] cmd) {
		
		// verifica registrazione a servizio RMI per CALLBACK
		if(!CALLBACK_REGISTRATION) {
			System.err.println("[ERRORE] effettuare registrazione a servizio RMI per CALLBACK");
			return;
		}
		// verifica totale argomenti
		if(cmd.length < 3) {
			System.err.println("[ERRORE] utilizzare sintassi: \"sendchatmsg <project_name> <msg>\".");
			return;
		}
		
		ClientChat th;
		// recupera gestore multicast associato al progetto
		synchronized(CHAT_READERS) {
			th = CHAT_READERS.get(cmd[1]);
		}
		if(th == null) {
			System.err.println("[ERRORE] puoi inviare messaggi solo alle chat dei progetti di cui sei membro.");
			return;
		}
		
		String msg = "";
		for(int i=2; i<cmd.length; i++)
			msg += cmd[i] + " ";
		
		// invia messaggio nella chat multicast
		th.sendMessages("<" + USERNAME + "> " + msg);
		System.out.println("[CHAT] messaggio inviato.");
	}
	
	
}
