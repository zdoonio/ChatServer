
package com.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * For now this class is intended to use
 * when agreeing on a key between two parties,
 * with distribution of keys from 
 * predistributed keys. 
 * 
 * This class represents an entity like Alice and Bob, 
 * which would be communicating.
 * 
 * 
 * @author Karol
 * 
 */
public class KeyAgreementEntity {

    public enum algorithms {AES, DES, DESede};
    public enum modes {ECB, CBC};
    
    public final String algorithm;
    public final String mode;
    public final String PADDING = "PKCS5Padding";
    
    /**
     * Algorithm for key encryption. 
     */
    public final String KEY_ALGO = "AES/CBC/PKCS5Padding";
    
    /**
     * Size of predistributed key.
     */
    public final int KEY_SIZE = 128 / 8;
    
    
    /**
     * used for encrypting the session key
     */
    private SecretKeySpec predistributedKey;
    
    /**
     * session key used for real encrypting 
     * and decrypting of messages.
     */
    private SecretKey sessionKey;
    
    private final int sessionKeyLen;
    
    
    
    /**
     * Assert which algorithm would one use to encrypt and decrypt messages,
     * meaning real communication.
     * 
     * @param algorithm
     * @param mode 
     */
    public KeyAgreementEntity(algorithms algorithm, modes mode) {
        
        switch (algorithm) {
            case AES:
                this.algorithm = "AES";
                this.sessionKeyLen = 128 / 8;
                break;
            case DES:
                this.algorithm = "DES";
                this.sessionKeyLen = 68 / 8;
                break;
            default:
                this.algorithm = "DESede";
                this.sessionKeyLen = 168 / 8;
                break;
        }
        
        if(mode.equals(modes.CBC)) {
            this.mode = "CBC";
        } else {
            this.mode = "ECB";
        }
        
        
    }
    
    public void setPredistributedKey(SecretKeySpec key) {
        this.predistributedKey = key;
    }
    
    
    
    public void generateSessionKey() {
        SecretKeySpec sk = generateKey(sessionKeyLen, algorithm);
        this.sessionKey = sk;
    }
    
    private SecretKeySpec generateKey(int keyLen, String algorithm) {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[keyLen];
        random.nextBytes(key);
        SecretKeySpec sk = new SecretKeySpec(key, algorithm);
        return sk;
    }
    
    public byte[] encryptSessionKey(IvParameterSpec iv) {
        try {
            Cipher cipher = Cipher.getInstance(KEY_ALGO);
            cipher.init(Cipher.ENCRYPT_MODE, predistributedKey, iv);
            byte[] sessionKeyByte = sessionKey.getEncoded();
            byte[] encrypted = cipher.doFinal(sessionKeyByte);
            return encrypted;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(KeyAgreementEntity.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public void decryptSessionKey(byte[] encSessionKey, IvParameterSpec iv) {
        
    }
    
}
