package org.example;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, SignatureException {
		final String KEY_IN_HEX_1 = "68544020247570407220244063724074";
		final String KEY_IN_HEX_2 = "54684020247570407220244063724074";
		final String KEY_IN_HEX_3 = "54684020247570407220244063727440";
		final String SHA_256_HASH_OF_CORRECT_KEY = "f28fe539655fd6f7275a09b7c3508a3f81573fc42827ce34ddf1ec8d5c2421c3";
		final String AES_ENCRYPTED_MESSAGE = "876b4e970c3516f333bcf5f16d546a87aaeea5588ead29d213557efc1903997e";
		final String CBC_INITIALIZATION_VECTOR = "656e6372797074696f6e496e74566563";

		byte[] keyInBytes1 = transformHEXStringToByteArray(KEY_IN_HEX_1);
		byte[] keyInBytes2 = transformHEXStringToByteArray(KEY_IN_HEX_2);
		byte[] keyInBytes3 = transformHEXStringToByteArray(KEY_IN_HEX_3);

		byte[] hashOfKeyByte1 = getCryptographicHash(keyInBytes1);
		byte[] hashOfKeyByte2 = getCryptographicHash(keyInBytes2);
		byte[] hashOfKeyByte3 = getCryptographicHash(keyInBytes3);

		// Getting hash list
		String[] hashList = {transformBytesToString(hashOfKeyByte1), transformBytesToString(hashOfKeyByte2), transformBytesToString(hashOfKeyByte3)};

		// Transform hashes to bytes
		byte[] aesMessageBytes = transformHEXStringToByteArray(AES_ENCRYPTED_MESSAGE);
		byte[] cbcVectorBytes = transformHEXStringToByteArray(CBC_INITIALIZATION_VECTOR);
		byte[] decryptedMessageBytes = {};

		for (String hash : hashList) {
			// If hashes are equal then decrypt message
			if (hash.equals(SHA_256_HASH_OF_CORRECT_KEY)) {
				decryptedMessageBytes = decryptMessage(keyInBytes2, cbcVectorBytes, aesMessageBytes);
			}
		}

		// Generation keypair (public + private)
		KeyPair keyPair = generateKeyPair();
		PrivateKey privateKey = keyPair.getPrivate();

		// Sign of decrypted message
		byte[] sign = signMessage(privateKey, decryptedMessageBytes);

		// Transform bytes of sign to string
		String transformedSignToString = transformBytesToString(sign);

		System.out.println("Decrypted Message as a string: " + new String(decryptedMessageBytes,
				StandardCharsets.UTF_8));
		System.out.println("Decrypted Message Bytes: " + transformBytesToString(decryptedMessageBytes));
		System.out.println("Public Key: " + transformBytesToString(keyPair.getPrivate().getEncoded()));
		System.out.println("Private Key: " + transformBytesToString(keyPair.getPublic().getEncoded()));
		System.out.println("The Sign: " + transformedSignToString);
	}

	public static byte[] transformHEXStringToByteArray(String hexString) {
		int hexLength = hexString.length();
		byte[] byteArray = new byte[hexLength / 2];

		for (int i = 0; i < hexLength; i += 2) {
			byteArray[i / 2] =
					(byte) ((Character.digit(hexString.charAt(i), 16) << 4) + (Character.digit(hexString.charAt(i + 1)
							, 16)));
		}

		return byteArray;
	}

	public static byte[] getCryptographicHash(byte[] keyInBytes) throws NoSuchAlgorithmException {
		try {
			MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
			return sha256.digest(keyInBytes);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return keyInBytes;
	}

	public static String transformBytesToString(byte[] hashInBytes) {
		StringBuilder hexInString = new StringBuilder(2 * hashInBytes.length);

		for (byte b : hashInBytes) {
			String hex = String.format("%02x", b);
			hexInString.append(hex);
		}

		return hexInString.toString();
	}

	public static byte[] decryptMessage(byte[] keyInBytes, byte[] cbcVectorInBytes, byte[] aesMessageInBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		SecretKeySpec secretKeySpec = new SecretKeySpec(keyInBytes, "AES");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(cbcVectorInBytes);

		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);

		return cipher.doFinal(aesMessageInBytes);
 	}

	 // Generation asymmetric keypair (public + private) using elliptic curve
	 public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		 keyPairGenerator.initialize(256);
		 KeyPair keyPair = keyPairGenerator.generateKeyPair();

		 return keyPair;
	 }

	 public static byte[] signMessage(PrivateKey privateKey, byte[] decryptedMessageBytes) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		 Signature signature = Signature.getInstance("SHA256withECDSA");
		 signature.initSign(privateKey);
		 signature.update(decryptedMessageBytes);
		 byte[] sign = signature.sign();

		 return sign;
	 }
}