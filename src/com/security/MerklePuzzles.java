/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Karol
 */
public class MerklePuzzles {
    
    // Algorithms available for this puzzles.
    public static enum algorithms {DES, DESede, AES};
    
    // Chosen algorithm
    private String algorithm;
    
    // Prefix for encrypting a message, e.g. "Puzzle#"
    private final String prefix;

    // the key length for encryption (in bits) - the actual value 
    // for which the random key would be computed, e.g.
    // in case of AES it is 32 and rest 96 bits is occupied by zeros.
    private int encKeyLen;
    
    // The actual length of the secret key for encryption (in bits)
    // e.g. in case of aes it's 128
    private int secKeyLen;
    
    // Corresponding key lengths in bytes
    private int encKeyLenBytes;
    private int secKeyLenBytes;
    
    // An instance of cipher, used for encryption and decryption
    private Cipher cipher;
    
    // A secure random generator, used in chossing a random key
    private final SecureRandom random;
    
    /**
     * Create an instance of merkle puzzles with a specified 
     * algorithm to be used for encryption and decryption, as well as
     * specified prefix to be used to encrypt the puzzles.
     * @param algo
     * @param pref 
     */
    public MerklePuzzles(algorithms algo, String pref) {
        try {
            switch(algo) {
                case DES :
                    setOptions("DES", 24, 68);
                    break;
                case AES :
                    setOptions("AES", 32, 128);
                    break;
                case DESede :
                    setOptions("DESede", 56, 192);
                    break;
                default :
                    setOptions("AES", 32, 128);
                    break;
            }
            
            cipher = Cipher.getInstance(algorithm);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        }
        random = new SecureRandom();
        prefix = pref;
    }
    
    /**
     * Set algorithm and key lengths.
     * @param algorithm
     * @param encKeyLen
     * @param secKeyLen 
     */
    private void setOptions(String algorithm, int encKeyLen, int secKeyLen) {
        this.algorithm = algorithm;
        this.encKeyLen = encKeyLen;
        this.encKeyLenBytes = encKeyLen / 8;
        this.secKeyLen = secKeyLen;
        this.secKeyLenBytes = secKeyLen / 8;
    }
    
    /**
     * Create a random string. Used for creating a key. 
     * @param bytes - number of bytes on which the random string should be stored
     * @return the random string
     */
    public String randomString(int bytes) {
        String k = new BigInteger(10000, random)
                .toString(32)
                .substring(0, bytes);
        return k;
        
    }
    
    /**
     * Choose random keys for encryption of the puzzles.
     * @return 
     */
    public SecretKey randomEncKey() {
        byte[] preKey = randomString(encKeyLenBytes).getBytes();
        byte[] realKey = new byte[secKeyLenBytes];
        
        System.arraycopy(preKey, 0, realKey, 0, encKeyLenBytes);
        
        SecretKey sks = new SecretKeySpec(realKey, algorithm);
        return sks;
    }
    
    /**
     * Encrypt a message with a secret key. Used when constructing puzzles.
     * @param key
     * @param message
     * @return an encryption of a message
     */
    public byte[] encrypt(SecretKey key, String message) {
        byte[] byteMsg = message.getBytes();
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ciphertext = cipher.doFinal(byteMsg);
            return ciphertext;
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    } 
    
    /**
     * Decrypt a ciphertext using a secret key. May be used for solving the puzzle.
     * @param key
     * @param ciphertext
     * @return a decyption of a ciphertext
     */
    public String decrypt(SecretKey key, byte[] ciphertext) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decipherBytes = cipher.doFinal(ciphertext);
            String plaintext = new String(decipherBytes);
            return plaintext;
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(MerklePuzzles.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * Makes one puzzle - encrypted (prefix || secret key || public key).
     * @param key - encryption key
     * @return one encrypted message - a puzzle
     */
    public byte[] puzzle(SecretKey key) {
        String secretKey = randomString(secKeyLenBytes);
        String publicKey = randomString(secKeyLenBytes);
        String plainPuzzle = prefix + secretKey + publicKey;
        byte[] puzzle = encrypt(key, plainPuzzle);
        return puzzle;
    }
    
    /**
     * Make puzzles. Beware of the memory usage. 
     * TODO : save puzzles into a file.
     * @param key - to be used for encryption
     * @param numOfPuzzles - number of puzzles to create
     * @return instance of ArrayList containing puzzles - encrypted messages.
     */
    public ArrayList<byte[]> puzzles(SecretKey key, int numOfPuzzles) {
        ArrayList<byte[]> puzzles = new ArrayList<byte[]>(numOfPuzzles);
        for(int i = 0; i < numOfPuzzles; i++) {
            puzzles.add(i, puzzle(key));
        }
        return puzzles;
    }
    
    /**
     * Get the algorithm to be used. Helps in solving.
     * @return 
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Get the prefix of the encrypted message.
     * @return 
     */
    public String getPrefix() {
        return prefix;
    }
    
    
    public static void main(String args[]) {
        MerklePuzzles mp = new MerklePuzzles(algorithms.AES, "Pref");
        SecretKey sk = mp.randomEncKey();
        
        ArrayList<byte[]> puzzles = mp.puzzles(sk, 100000);
        System.out.println(puzzles.size());
        
    }
    
    
}
