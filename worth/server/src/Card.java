import java.io.Serializable;
import java.util.ArrayList;


public class Card implements Serializable {
	
	private final static long serialVersionUID = 20000;
	
	// descrizione della card
	private final String desc;
	// cronologia spostamenti della card nel progetto (nomi delle tabelle)
	private final ArrayList<String> history;
	
	
	// COSTRUTTORE
	public Card(String desc) {
		this.desc = desc;
		this.history = new ArrayList<String>(4);
		// lista inizialmente in stato di TODO
		this.history.add("todo");
	}
	
	// restituisce la descrizione della card
	public String getDesc() {
		return this.desc;
	}
	
	// restituisce la lista con la cronologia degli stati della card (nomi delle tabelle)
	public String getHistory(){
		String s = "";
		int i;
		
		for(i=0; i<this.history.size()-1; i++)
			s += this.history.get(i) + " -> ";
		s += this.history.get(i);
		
		return s;
	}
	
	// restituisce lo stato attuale della card (nome della tabella)
	public String getActualState() {
		return this.history.get(this.history.size()-1);
	}
	
	// insierisce l'attuale stato aggiornato della card (nome della tabella)
	public void updateHistory(String state) {
		this.history.add(state);
	}
	
	
}
