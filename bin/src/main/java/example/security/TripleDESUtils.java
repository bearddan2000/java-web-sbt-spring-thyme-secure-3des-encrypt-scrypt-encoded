package example.security;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;

public class TripleDESUtils {
  final static String digestName = "md5";

  static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(n);
      SecretKey key = keyGenerator.generateKey();
      return key;
  }

  public static String generateSalt(int n) throws NoSuchAlgorithmException {
      SecretKey key = generateKey(n);
      return java.util.Base64.getEncoder().encodeToString(key.getEncoded());
  }

  public static String encrypt(String message, String digestPassword) throws Exception {
      final MessageDigest md = MessageDigest.getInstance(digestName);
      final byte[] digestOfPassword = md.digest(digestPassword
              .getBytes("utf-8"));
      final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
      for (int j = 0, k = 16; j < 8;) {
          keyBytes[k++] = keyBytes[j++];
      }

      final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
      final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
      final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);

      final byte[] plainTextBytes = message.getBytes("utf-8");
      final byte[] cipherText = cipher.doFinal(plainTextBytes);

      return new String(cipherText, "utf-8");
  }
}
