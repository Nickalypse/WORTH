import java.rmi.Remote;
import java.rmi.RemoteException;


public interface ServerCallbackInterface extends Remote {
	
	/** [CLIENT --> SERVER] **/
	
	// client si registra per ricevere le CALLBACK
	// comunica il proprio STUB RMI
	// e dati di accesso codificati con chiave RSA pubblica del server
	public String registrazione_callback(ClientCallbackInterface client, String dataRSA) throws RemoteException;
	
	
}
