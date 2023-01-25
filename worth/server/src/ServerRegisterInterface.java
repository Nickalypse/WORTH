import java.rmi.Remote;
import java.rmi.RemoteException;


public interface ServerRegisterInterface extends Remote {
	
	// effettua la registrazione di un nuovo utente
	// username e password sono codificati con RSA usando la chiave pubblica del server
	// effettua CALLBACK agli utenti online per aggiornarli sul nuovo utente
	// restituisce stringa con esito dell'operazione
	public String register(String usernameRSA, String passwordRSA) throws RemoteException;
	
	
}
