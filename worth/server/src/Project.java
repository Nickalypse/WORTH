import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;


public class Project {	
	
	// lista con username degli utenti membri del progetto
	private final ArrayList<String> members;
	
	// tabelle che associano il nome delle cards alla loro istanza
	private final HashMap<String, Card> TODO;
	private final HashMap<String, Card> INPROGRESS;
	private final HashMap<String, Card> TOBEREVISED;
	private final HashMap<String, Card> DONE;
	
	// indirizzo IP multicast della chat dei membri del progetto
	private final String chat_ip;
	// chiave AES per la codifica dei messaggi inviati nella chat
	private final String chat_aes_key;
	
	
	// COSTRUTTORE
	public Project(String chat_ip, String chat_aes_key) {
		this.members		=	new ArrayList<String>();
		this.TODO			=	new HashMap<String, Card>();
		this.INPROGRESS		=	new HashMap<String, Card>();
		this.TOBEREVISED	=	new HashMap<String, Card>();
		this.DONE			=	new HashMap<String, Card>();
		this.chat_ip		=	chat_ip;
		this.chat_aes_key	=	chat_aes_key;
	}
	
	
	// restituisce true se il progetto è eliminabile (tutte le card sono in lista DONE)
	public boolean isDeletable() {
		return (this.TODO.size() == 0) && (this.INPROGRESS.size() == 0) && (this.TOBEREVISED.size() == 0);
	}
	
	// aggiunge l'username alla lista dei membri
	public void addMember(String username) {
		this.members.add(username);
	}
	
	// restituisce true se l'username è di un utente membro del progetto
	public boolean isMember(String username) {
		return this.members.contains(username);
	}
	
	// restituisce array con i membri del progetto
	public String[] getArrayMembers() {
		String[] lista = new String[this.members.size()];
		for(int i=0; i<lista.length; i++)
			lista[i] = this.members.get(i);
		return lista;
	}
	
	// aggiunge una card al progetto nella tabella corretta
	public void addCard(String card_name, Card c) {
		// tabella scelta in base allo stato attuale della card
		switch(c.getActualState()) {
			case("todo"):
				this.TODO.put(card_name, c);
				break;
			case("inprogress"):
				this.INPROGRESS.put(card_name, c);
				break;
			case("toberevised"):
				this.TOBEREVISED.put(card_name, c);
				break;
			case("done"):
				this.DONE.put(card_name, c);
				break;
		}
	}
	
	// restituisce true se la card fa parte del progetto
	public boolean containsCard(String card_name) {
		return	this.TODO.containsKey(card_name)			||
				this.INPROGRESS.containsKey(card_name)		||
				this.TOBEREVISED.containsKey(card_name)		||
				this.DONE.containsKey(card_name);
	}
	
	// restituisce la lista con tutti i nomi delle cards nel progetto
	public ArrayList<String> getCards(){
		ArrayList<String> lista = new ArrayList<String>();
		lista.addAll(this.TODO.keySet());
		lista.addAll(this.INPROGRESS.keySet());
		lista.addAll(this.TOBEREVISED.keySet());
		lista.addAll(this.DONE.keySet());
		return lista;
	}
	
	// restituisce una card del progetto dato il nome
	public Card getCardByName(String card_name) {
		Card c = this.TODO.get(card_name);
		if(c == null) c = this.INPROGRESS.get(card_name);
		if(c == null) c = this.TOBEREVISED.get(card_name);
		if(c == null) c = this.DONE.get(card_name);
		return c;
	}
	
	// restituisce true se la tabella contiene il nome della card
	public boolean listContainsCard(String state, String card_name) {
		switch(state) {
			case("todo"):
				return this.TODO.containsKey(card_name);
			case("inprogress"):
				return this.INPROGRESS.containsKey(card_name);
			case("toberevised"):
				return this.TOBEREVISED.containsKey(card_name);
			case("done"):
				return this.DONE.containsKey(card_name);
			default:
				return false;
		}
	}
	
	// sposta una card del progetto da una tabella all'altra
	public void moveCard(String card_name, String start, String end) {
		
		Card c = null;
		
		switch(start) {
			case("todo"):
				c = this.TODO.remove(card_name);
				break;
			case("inprogress"):
				c = this.INPROGRESS.remove(card_name);
				break;
			case("toberevised"):
				c = this.TOBEREVISED.remove(card_name);
				break;
			case("done"):
				c = this.DONE.remove(card_name);
				break;
		}
		
		switch(end) {
			case("todo"):
				this.TODO.put(card_name, c);
				break;
			case("inprogress"):
				this.INPROGRESS.put(card_name, c);
				break;
			case("toberevised"):
				this.TOBEREVISED.put(card_name, c);
				break;
			case("done"):
				this.DONE.put(card_name, c);
				break;
		}
	}
	
	// restituisce IP multicast della chat membri del progetto
	public String getChatIP() {
		return this.chat_ip;
	}
	
	// restituisce la chiave AES da utilizzare nella comunicazione multicast
	public String getChatAESKey() {
		return this.chat_aes_key;
	}
	
	// invia messaggio del server nella chat del progetto
	public void sendChatMsg(String msg) {
		try {
			// istanzia indirizzo data la stringa con ip
			InetAddress address = InetAddress.getByName(this.chat_ip);
			// istanzia socket per multicast su porta specificata
			MulticastSocket socket = new MulticastSocket(ServerMain.PORT_MULTICAST);
			// pacchetti elaborati localmente
			socket.setTimeToLive(0);
			
			// codifica messaggio del server con chiave AES della chat
			String msgAES = Security.aes_cripta(this.chat_aes_key, msg);
			// conversione stringa in array di byte
			byte[] buffer = msgAES.getBytes();
			
			// creazione pacchetto UDP
			DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, ServerMain.PORT_MULTICAST);
			// invia pacchetto UDP
			socket.send(packet);
			// chiusura socket
			socket.close();
		}
		catch(IOException e) {
			System.err.println("[ERRORE] impossibile inviare messaggi nella chat del progetto.");
			System.exit(-1);
		}
	}
	
	
}
