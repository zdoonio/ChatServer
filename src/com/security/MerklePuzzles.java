package com.security;

import java.security.SecureRandom;
import java.util.ArrayList;


/**
 *
 * @author Karol
 * TODO: Enable different encryption algorithms for encryption of puzzles.
 */
public class MerklePuzzles {
    
    // Algorithm to be used to encrypt/decrypt puzzles. 
    public static final String MERKLE_ALGORITHM = "AES/GCM/NoPadding";
    
    // To store the keys randomly choosed by Alice.
    private ArrayList<byte[]> encryptionKeys;
    
    // To store secret keys encrypted in a puzzle.
    private ArrayList<byte[]> secretKeys;
    
    // To store public keys, used to exchange between Alice and Bob.
    private ArrayList<byte[]> publicKeys;
    
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
    
    /**
     * Fill the field encryptionKeys with random keys.
     */
    public void setEncryptionKeys() 
    {
       encryptionKeys = new ArrayList<byte[]>();
       SecureRandom random = new SecureRandom();
       
        for (int i = 0; i < NUM_OF_PUZZLES; i++) {
            byte[] encKey = new byte[ENC_KEY_BITS / 8];
            random.nextBytes(encKey);
            encryptionKeys.add(encKey);
        }
    }
    
    
    public static void main(String args[]) {
        MerklePuzzles mp = new MerklePuzzles();
        mp.setEncryptionKeys();
        
        for(byte[] key : mp.encryptionKeys) {
            for(byte b : key) {
                System.out.print(String.valueOf(b));
            }
            System.out.println();
        }
     
    }
    
    
}
