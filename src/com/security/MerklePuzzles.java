package com.security;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;


/**
 *
 * @author Karol
 * TODO: Enable different encryption algorithms for encryption of puzzles.
 */
public class MerklePuzzles {
    
    // Algorithm to be used to encrypt/decrypt puzzles. 
    public static final String MERKLE_ALGORITHM = "AES/GCM/NoPadding";
    
    // To store the keys randomly choosed by Alice.
    private ArrayList<Key> encryptionKeys;
    
    // To store secret keys encrypted in a puzzle.
    private ArrayList<Key> secretKeys;
    
    // To store public keys, used to exchange between Alice and Bob.
    private ArrayList<Key> publicKeys;
    
    // Puzzles - encrypted messages.
    private ArrayList<byte[]> puzzles;
    
    // Public key that is send from Bob to Alice.
    private byte[] publicKey;
    
    // number of bits for encryptionKeys, for AES128 it's 32 bits
    // this field for now can be final, when TODO done can be set 
    // individually for each algortihm
    private static final int ENC_KEY_BITS = 32;
    
    // number of bits for secret and public keys, 
    // for AES128 it's 128 bits
    private static final int PUB_SEC_KEY_BITS = 128;
    
    // Number of puzzles to be prepared (also number of secret, 
    // public and encryption keys)
    private static final int NUM_OF_PUZZLES = (int) Math.pow(2, ENC_KEY_BITS);
    
    // Message prefix used to encrypt and check decryption
    private static final String PREFIX = "Puzzle#"; 
    
   
    public void setEncryptionKeys() 
    {
       encryptionKeys = randomKeys(ENC_KEY_BITS, NUM_OF_PUZZLES);
    }
    
    public void setSecretKeys() 
    {
       secretKeys = randomKeys(PUB_SEC_KEY_BITS, NUM_OF_PUZZLES);
    }
    
    public void setPublicKeys()
    {
       publicKeys = randomKeys(PUB_SEC_KEY_BITS, NUM_OF_PUZZLES);
    }
    
    /**
     *
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     */
    public void setPuzzles() throws NoSuchAlgorithmException, 
            NoSuchPaddingException, InvalidKeyException {
        
        puzzles = new ArrayList<byte[]>();
        Cipher cipher = Cipher.getInstance(MERKLE_ALGORITHM);
        
        for(int i = 0; i < NUM_OF_PUZZLES; i++) {
           Key key = encryptionKeys.get(i);
           cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        
    }
    
    /**
     * 
     * 
     * @param bits  the number of bits for storing the message
     * @param loop  how many messages to be produced
     * @return      an instance of ArrayList containing random keys
     */
    private static ArrayList<Key> randomKeys(int bits, int loop) {
        
        int bytes = bits / 8;
        ArrayList<Key> keys = new ArrayList<Key>();
        SecureRandom random = new SecureRandom();
        
        for (int i = 0; i < loop; i++) {
            byte[] message = new byte[bytes];
            random.nextBytes(message);
            Key key = new SecretKeySpec(message, 0, message.length, "AES");
            keys.add(key);
        }
        
        return keys;
    }
    
    /**
     *  Test the class working
     * @param args
     */
    public static void main(String args[]) {
     MerklePuzzles mp = new MerklePuzzles();
     mp.setEncryptionKeys();

     for(Key key : mp.encryptionKeys) {
             System.out.print(String.valueOf(key));
         
         System.out.println();
     }

 }

 
    
    
}
