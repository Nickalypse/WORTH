import java.rmi.Remote;
import java.rmi.RemoteException;


public interface ClientCallbackInterface extends Remote {
	
	/** SERVER --> CLIENT **/
	
	// client aggiorna strutture locali con lista utenti e loro stato
	public void notifica_cambiamento_stato_utente(String msgAES) throws RemoteException;
	
	// client istanzia un ClientChat thread per la gestione della chat di progetto
	public void notifica_nuova_chat_progetto(String msgAES) throws RemoteException;
	
	// client termina il ClientChat thread che gestiva la chat di progetto
	public void notifica_chiusura_chat_progetto(String msgAES) throws RemoteException;
	
	
}
