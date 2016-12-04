
package com.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Karol
 * TODO : serializable public key, enable CBC mode, and encryption defferent than DES and DESede
 */
public class DiffieHellman {
    
    private DHPublicKey publicKey;
    private DHPrivateKey privateKey;
    
    private DHPublicKey receivedPublicKey;
    
    private byte[] secretKey;
    
    // Used when encrypting or decrypting with CBC mode
    private IvParameterSpec iv;
    
    public void generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            SecureRandom random = SecureRandom.getInstanceStrong();
            keyPairGenerator.initialize(1024, random);
            final KeyPair keyPair = keyPairGenerator.generateKeyPair();
            publicKey = (DHPublicKey) keyPair.getPublic();
            privateKey = (DHPrivateKey) keyPair.getPrivate();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * TODO : manage a serialization of an object
     * @return 
     */
    public DHPublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * TODO: Receive a serialized key.
     * @param publicKey 
     */
    public void receivePublicKey(DHPublicKey publicKey) {
        receivedPublicKey = publicKey;
    }
    
    /**
     * Generate a secret key used for encryption between two parties.
     */
    public void generateSharedSecret() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(privateKey);
            keyAgreement.doPhase(receivedPublicKey, true);
            secretKey = keyAgreement.generateSecret();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public IvParameterSpec generateIV(Cipher cipher) {
        try {
            SecureRandom randomSecureRandom = SecureRandom.getInstance("SHA1PRNG");
            byte[] ivGen = new byte[cipher.getBlockSize()];
            randomSecureRandom.nextBytes(ivGen);
            
            IvParameterSpec ivParams = new IvParameterSpec(ivGen);
            return ivParams;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public byte[] encrypt(final String message, 
            final String keyAlgorithm, final String cipherAlgorithm,
            final String mode) {
        
        try {
            final SecretKey key = shortenKey(secretKey, keyAlgorithm);
            final Cipher cipher  = Cipher.getInstance(cipherAlgorithm);
            
            if(mode.equals("CBC")) {
                iv = generateIV(cipher);
                cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            } else {                
                cipher.init(Cipher.ENCRYPT_MODE, key);
            }
            
            
            final byte[] encryptedMessage = cipher.doFinal(message.getBytes());
            return encryptedMessage;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }  catch (IllegalBlockSizeException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public String decrypt(final byte[] ciphertext,
            final String keyAlgorithm, final String cipherAlgorithm, 
            final String mode) {
        try {
            final SecretKey key = shortenKey(secretKey,keyAlgorithm);
            final Cipher        cipher;
            
            if(mode.equals("CBC")) {
                cipher  = Cipher.getInstance(cipherAlgorithm, "BC");
                cipher.init(Cipher.DECRYPT_MODE, key, iv);
            }
            else {
                cipher = Cipher.getInstance(cipherAlgorithm);
                cipher.init(Cipher.DECRYPT_MODE, key);
            }
                
            
            String secretMessage = new String(cipher.doFinal(ciphertext));
            return secretMessage;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidAlgorithmParameterException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchProviderException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public SecretKey shortenKey(final byte[] longKey, String keyAlgorithm) {
        try {
            final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            final SecretKeySpec  keySpec  = new SecretKeySpec(longKey, keyAlgorithm);
            return keyFactory.generateSecret(keySpec);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    } 

    
    
    public static void main(String[] args) {
        
        String keyalgo = "DESede";
        String cipheralgo = "DESede/ECB/PKCS5Padding";
        String mode = "ECB";
        
        DiffieHellman df = new DiffieHellman();
        df.generateKeys();
        
        DiffieHellman df2 = new DiffieHellman();
        df2.generateKeys();
        df.receivePublicKey(df2.getPublicKey());
        
        df2.receivePublicKey(df.getPublicKey());
        
        df.generateSharedSecret();
        df2.generateSharedSecret();
        
        byte[] encryption = df.encrypt("Co chciałeś, ążźćńópqrś?", keyalgo, cipheralgo, mode);
        String decryption = df2.decrypt(encryption, keyalgo, cipheralgo, mode);
        
        System.out.println(decryption);
        
    }
    
    
    
}
