

public class Util {
	
	public static final int MIN_LENGTH_NAME = 3;
	public static final int MAX_LENGTH_NAME = 24;
	
	public static final int MIN_LENGTH_PASSWORD = 8;
	public static final int MAX_LENGTH_PASSWORD = 32;
	
	public static final int MIN_LENGTH_CARD_DESC = 3;
	public static final int MAX_LENGTH_CARD_DESC = 256;
	
	
	// verifica se la stringa rappresenta un nome utente/progetto/card valido
	public static boolean checkValidName(String name) {
		if(name == null) return false;
		if(!name.trim().equals(name)) return false;
		if(name.length() < MIN_LENGTH_NAME) return false;
		if(name.length() > MAX_LENGTH_NAME) return false;
		if(Character.isDigit(name.charAt(0))) return false;
		if(name.charAt(0) == '_') return false;
		if(!name.matches("[a-z0-9_]+")) return false;
		return true;
	}
	
	// verifica se la stringa rappresenta una password valida
	public static boolean checkValidPassword(String password) {
		if(password == null) return false;
		if(!password.trim().equals(password)) return false;
		if(!password.matches("[A-Za-z0-9_#@&%$]+")) return false;
		
		String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[_#@&%$])(?=\\S+$).{";
		regex += MIN_LENGTH_PASSWORD + "," + MAX_LENGTH_PASSWORD + "}$";
		
		return password.matches(regex);
	}
	
	// verifica se la stringa rappresenta una descrizione di card valida
	public static boolean checkValidCardDesc(String desc) {
		if(desc == null) return false;
		if(!desc.trim().equals(desc)) return false;
		if(desc.length() < MIN_LENGTH_CARD_DESC) return false;
		if(desc.length() > MAX_LENGTH_CARD_DESC) return false;
		return true;
	}
	
	// restituisce true se la stringa è uno stato valido della card
	public static boolean isValidState(String state) {
		if(state.equals("todo")) return true;
		if(state.equals("inprogress")) return true;
		if(state.equals("toberevised")) return true;
		if(state.equals("done")) return true;
		return false;
	}
	
	// restituisce true se lo spostamento tra stati delle cards è valido
	public static boolean isValidMove(String start, String end) {
		if(start.equals("done")) return false;
		if(start.equals(end)) return false;
		if(start.equals("todo") && !end.equals("inprogress")) return false;
		if(start.equals("inprogress") && end.equals("todo")) return false;
		if(start.equals("toberevised") && end.equals("todo")) return false;
		return true;
	}
	
	
}
