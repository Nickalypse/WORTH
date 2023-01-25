import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.io.FileOutputStream;
import java.util.Base64;


public class Security {
	
	public static final int			RSA_KEY_SIZE	=	2048;
	public static final int			AES_KEY_SIZE	=	128;
	public static final Charset		CHAR_SET		=	StandardCharsets.UTF_8;
	
	
	/*** SHA-256 *********************************************************************/
	
	// genera hash in base64 di una stringa con SHA-256
	public static String sha256(String msg) {
		try {
			MessageDigest sha = MessageDigest.getInstance("SHA-256");
			byte[] hash_byte = sha.digest(msg.getBytes(CHAR_SET));
			String hash = Base64.getEncoder().encodeToString(hash_byte);
			return hash;
		}
		catch(Exception e) {}
		return null;
	}
	
	
	/*** AES *************************************************************************/
	
	// genera chiave simmetrica per AES codificata in base64
	public static String aes_genera_chiave() {
		try {
			KeyGenerator key_gen = KeyGenerator.getInstance("AES");
			key_gen.init(AES_KEY_SIZE);
			byte[] key_byte = key_gen.generateKey().getEncoded();
			String key = Base64.getEncoder().encodeToString(key_byte);
			return key;
		}
		catch(Exception e) {}
		return null;
	}
	
	// codifica stringa con AES
	public static String aes_cripta(String key64, String msg) {
		try {
			// conversione stringa in array di bytes
			byte[] key64_byte = key64.getBytes();
			// decodifica base64 dell'array di byte
			byte[] key = Base64.getDecoder().decode(key64_byte);
			
			SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			
			byte[] x = cipher.doFinal(msg.getBytes(CHAR_SET));
			String encrypt = Base64.getEncoder().withoutPadding().encodeToString(x);
			
			return encrypt;
		} catch(Exception e) {}
		return null;
	}
	
	// decodifica stringa con AES
	public static String aes_decripta(String key64, String encrypted) {
		try {
			// conversione stringa in array di bytes
			byte[] key64_byte = key64.getBytes();
			// decodifica base64 dell'array di byte
			byte[] key = Base64.getDecoder().decode(key64_byte);
			
			SecretKeySpec k = new SecretKeySpec(key, "AES");
			
			Cipher c = Cipher.getInstance("AES");
			c.init(Cipher.DECRYPT_MODE, k);
			byte[] decodedValue = java.util.Base64.getDecoder().decode(encrypted);
			byte[] decValue = c.doFinal(decodedValue);
			String decryptedValue = new String(decValue, CHAR_SET);
			return decryptedValue;
		} catch (Exception e) {}
		return null;
	}
	
	
	/*** RSA *************************************************************************/
	
	// genera coppia di chiavi asimmetriche per RSA (pubblica-privata)
	public static KeyPair rsa_genera_chiavi() {
		try {
			KeyPairGenerator key_gen = KeyPairGenerator.getInstance("RSA");
			key_gen.initialize(RSA_KEY_SIZE);
			return key_gen.generateKeyPair();
		}
		catch(Exception e) {}
		return null;
	}
	
	// salva coppia di chiavi asimmetriche per RSA su file
	public static void rsa_salva_chiavi_su_file(KeyPair chiavi, String path) {
		
		byte[] pub_key = chiavi.getPublic().getEncoded();
		byte[] priv_key = chiavi.getPrivate().getEncoded();
		
		System.out.println(pub_key.length + "\n" + priv_key.length);
		
		try(
			FileOutputStream out_pub_key = new FileOutputStream(path + "/pub_key");
			FileOutputStream out_priv_key = new FileOutputStream(path + "/priv_key");
		){
			out_pub_key.write(pub_key);
			out_priv_key.write(priv_key);
		}
		catch(IOException e) {}
	}
	
	// lettura chiave rivata da file
	public static PrivateKey rsa_importa_priv_key(String path) {
		
		try {
			byte[] key_byte = Files.readAllBytes(Paths.get(path + "/priv_key"));
			PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec(key_byte);
			KeyFactory costruttore = KeyFactory.getInstance("RSA");
			return costruttore.generatePrivate(key_spec);
		}
		catch(Exception e) {}
		return null;
	}
	
	// lettura chiave pubblica RSA da file
	public static PublicKey rsa_importa_pub_key(String path) {
		
		try {
			byte[] key_byte = Files.readAllBytes(Paths.get(path + "/pub_key"));
		    X509EncodedKeySpec key_spec = new X509EncodedKeySpec(key_byte);
		    KeyFactory costruttore = KeyFactory.getInstance("RSA");
		    return costruttore.generatePublic(key_spec);
		}
		catch(Exception e) {}
		return null;
	}
	
	// codifica di una stringa con RSA
	public static String rsa_cripta(Key key, String msg) {
		try {
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.ENCRYPT_MODE, key);
			byte[] cript = rsa.doFinal(msg.getBytes(CHAR_SET));
			return Base64.getEncoder().encodeToString(cript);
		}
		catch(Exception e) {}
		return null;
	}
	
	// decodifica di una stringa con RSA
	public static String rsa_decripta(Key key, String cript) {
		try {
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");			
			rsa.init(Cipher.DECRYPT_MODE, key);
			byte[] cript_byte = Base64.getDecoder().decode(cript.getBytes());
			byte[] msg_byte = rsa.doFinal(cript_byte);
			return new String(msg_byte,CHAR_SET);
		}
		catch(Exception e) {}
		return null;
	}
	
}

