
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Sample_New {
	
	/*
	 * weak hash MD5
	 * no salt
	 */	
	private static byte[] hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        return md.digest();
	}
	
	
	/*
	 * weak hash SHA1
	 * weak PRNG random
	 * static seed 0
	 * short salt, 4 bytes
	 */
	private static byte[] saltHashPassword(String password) throws NoSuchAlgorithmException {
        Random r = new Random(0);
        byte [] salt = new byte[4];
		r.nextBytes(salt);
		byte[] saltedPassword = new byte[password.length() + salt.length];
		System.arraycopy(password.getBytes(), 0, saltedPassword, 0, password.length());
		System.arraycopy(salt, 0, saltedPassword, password.length(), salt.length);
        MessageDigest md = MessageDigest.getInstance("SHA1");
        md.update(saltedPassword);
        return md.digest();
	}

	
	/*
	 * custom salt derived from password
	 * fewer iterations password length
	 */
 	private static PBEKeySpec getPBEParameterSpec(String password) throws Throwable {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] saltGen = md.digest(password.getBytes());
        byte[] salt = new byte[8];
        System.arraycopy(saltGen, 0, salt, 0, 8);
        int iteration = password.toCharArray().length + 1;
        return new PBEKeySpec(password.toCharArray(), salt, iteration);
	}
 	
 	
 	/*use of base64 encoding to obfuscate passsword */
 	private static byte[] encodePassword(String password) {
 		
 		Base64.Encoder encoder = Base64.getEncoder();  
 		return encoder.encode(password.getBytes());

 	}
 	
 	/*use of AES to encrypt password */
 	private static byte[] encryptPassword(String password, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

 		
 		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
 		SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
 		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
 		return cipher.doFinal(password.getBytes());
 		
 	}
 	
 	public static void main(String args[]) throws Throwable {
 		String password = "password";
 		String key = "abcdefghijklmnop";
 		System.out.println(hashPassword(password));
 		System.out.println(saltHashPassword(password));
 		System.out.println(encodePassword(password));
 		System.out.println(getPBEParameterSpec(password));
 		System.out.println(encryptPassword(password, key));
 		
 	}

}