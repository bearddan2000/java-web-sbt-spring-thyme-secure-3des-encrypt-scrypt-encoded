package example.security;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

public class TripleDESPasswordEncoder extends org.springframework.security.crypto.scrypt.SCryptPasswordEncoder
  implements PasswordEncoder {

    String digestPassword = null;

    public TripleDESPasswordEncoder() throws NoSuchAlgorithmException {
      super();
      this.digestPassword = TripleDESUtils.generateSalt(256);
    }

    @Override
    public java.lang.String encode(java.lang.CharSequence rawPassword)
    {
      try {
        String res = TripleDESUtils.encrypt(rawPassword.toString(), this.digestPassword);
        return super.encode(res);//BCrypt.hashpw(res, BCrypt.gensalt());
      } catch(Exception e) {}
      return super.encode(rawPassword);
    }

    @Override
    public boolean matches(java.lang.CharSequence rawPassword, java.lang.String encodedPassword)
    {
     try {
       String res = TripleDESUtils.encrypt(rawPassword.toString(), this.digestPassword);
       return super.matches(res, encodedPassword);
     } catch(Exception e) {}
     return false;
    }
}
