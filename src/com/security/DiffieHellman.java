
package com.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Karol
 * TODO : serializable public key, handle different padding
 */
public class DiffieHellman {
    
    private DHPublicKey publicKey;
    private DHPrivateKey privateKey;
    
    private DHPublicKey receivedPublicKey;
    
    private byte[] secretKey;
    
    private SecureRandom random;
    
    
    public void generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            random = SecureRandom.getInstanceStrong();
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
    
    
    public byte[] encrypt(final String message, 
            final String keyAlgorithm, final String cipherAlgorithm)  {
        
        try {
            final Key key = shortenKey(secretKey, keyAlgorithm);
            final Cipher cipher  = Cipher.getInstance(cipherAlgorithm);
                       
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
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
        } catch (InvalidKeySpecException ex) { 
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public byte[] encrypt(final String message, 
            final String keyAlgorithm, final String cipherAlgorithm,
            final IvParameterSpec iv) {
        
        try {
            final Key key = shortenKey(secretKey, keyAlgorithm);
            final Cipher cipher  = Cipher.getInstance(cipherAlgorithm);
                       
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            
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
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
        
    }
    
    public String decrypt(final byte[] ciphertext,
            final String keyAlgorithm, final String cipherAlgorithm) {
        
        try {
            final Key key = shortenKey(secretKey,keyAlgorithm);
            final Cipher cipher = Cipher.getInstance(cipherAlgorithm);

            cipher.init(Cipher.DECRYPT_MODE, key);
          
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
        } catch (InvalidKeySpecException ex) {  
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    
    }
    
    public String decrypt(final byte[] ciphertext,
            final String keyAlgorithm, final String cipherAlgorithm, 
             IvParameterSpec iv) {
        try {
            final Key key = shortenKey(secretKey,keyAlgorithm);
            final Cipher cipher = Cipher.getInstance(cipherAlgorithm);

            cipher.init(Cipher.DECRYPT_MODE, key, iv, random);
          
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
        } catch (InvalidKeySpecException ex) { 
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public Key shortenKey(final byte[] longKey, String keyAlgorithm) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException { 
        
        if(keyAlgorithm.equals("AES")) {
            int AES_KEY_LEN = 128 / 8;
            final byte[] key = new byte[AES_KEY_LEN];
            System.arraycopy(longKey, 0, key, 0, AES_KEY_LEN);
            final Key keySpec = new SecretKeySpec(key, keyAlgorithm);
            return keySpec;   
        } else {
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(keyAlgorithm);
            KeySpec keySpec = new SecretKeySpec(longKey, keyAlgorithm);
            Key key = keyFactory.generateSecret(keySpec);
            return key;
        }
        
        
    } 

    
    
    public static void main(String[] args) {
        
        String keyalgo = "AES";
        String cipheralgo = "AES/ECB/PKCS5Padding";
        
        try {
            int blocksize = Cipher.getInstance(cipheralgo).getBlockSize();
            DiffieHellman df = new DiffieHellman();
            df.generateKeys();

            DiffieHellman df2 = new DiffieHellman();
            df2.generateKeys();
            df.receivePublicKey(df2.getPublicKey());

            df2.receivePublicKey(df.getPublicKey());

            df.generateSharedSecret();
            df2.generateSharedSecret();

            IvParameterSpec iv = IvGenerator.generateIV(blocksize);

            byte[] encryption = df.encrypt("Co chciałeś, ążźćńópqrś?", keyalgo, cipheralgo);
            String decryption = df2.decrypt(encryption, keyalgo, cipheralgo);

            System.out.println(decryption);
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(DiffieHellman.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
        
    }
    
    
    
}
