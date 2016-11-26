package com.security;

import com.utils.ArrayUtils;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
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
    
    // Key zero prefix used for encryption
    private static final byte[] ENC_KEY_PREFIX = new byte[(PUB_SEC_KEY_BITS - ENC_KEY_BITS) / 8]; 
    
   
    public void setEncryptionKeys() 
    {
       encryptionKeys = randomKeys(ENC_KEY_BITS, NUM_OF_PUZZLES, ENC_KEY_PREFIX);
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
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public void setPuzzles() throws NoSuchAlgorithmException, 
            NoSuchPaddingException, InvalidKeyException, 
            IllegalBlockSizeException, BadPaddingException {
        
        puzzles = new ArrayList<byte[]>();
        byte[] prefix = PREFIX.getBytes();
        byte[] keyPrefix = new byte[(PUB_SEC_KEY_BITS - ENC_KEY_BITS) / 8];
        
        // Initialize the cipher
        Cipher cipher = Cipher.getInstance(MERKLE_ALGORITHM);
        
        for(int i = 0; i < NUM_OF_PUZZLES; i++) {
           
           Key encKey = encryptionKeys.get(i);
           byte[] pubKey = publicKeys.get(i).getEncoded();
           byte[] secKey = secretKeys.get(i).getEncoded();
           
           cipher.init(Cipher.ENCRYPT_MODE, encKey);
           
           byte[] message = ArrayUtils.concatenate(prefix, 
                   ArrayUtils.concatenate(pubKey, secKey));
           
           byte[] puzzle = cipher.doFinal(message);

           puzzles.add(puzzle);
        }
        
    }
    
    public void solvePuzzles() {
        
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
     * 
     * @param bits   the number of bits for storing the random part of a key
     * @param loop   how many keys to be produced
     * @param prefix the prefix of a key 
     * @return an instance of ArrayLisrt contaning random keys.
     */
    private static ArrayList<Key> randomKeys(int bits, int loop, byte[] prefix)
    {
        int bytes = bits / 8;
        ArrayList<Key> keys = new ArrayList<Key>();
        SecureRandom random = new SecureRandom();
        
        for (int i = 0; i < loop; i++) {
            byte[] message = new byte[bytes];
            random.nextBytes(message);
            byte[] wholeMsg = ArrayUtils.concatenate(prefix, message);
            Key key = new SecretKeySpec(wholeMsg, 0, wholeMsg.length, "AES");
            keys.add(key);
        }
        
        return keys;
    }
    
    
    /**
     *  Test the class working
     * @param args
     */
    public static void main(String args[]) {
     
        SecureRandom random = new SecureRandom();
        byte[] msg1 = new byte[8];
        random.nextBytes(msg1);
        byte[] msg2 = new byte[8];
        
        byte[] msg = ArrayUtils.concatenate(msg2, msg1);
        
        for(byte b : msg) {
            System.out.print(b);
        }
        
        System.out.println();
        Key key = new SecretKeySpec(msg, 0, msg.length, "AES");
        
        for(byte b : key.getEncoded()) {
            System.out.print(b);
        }
        
        System.out.println();
 }

 
    
    
}
