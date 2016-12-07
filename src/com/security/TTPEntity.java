/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import javax.crypto.SecretKey;

/**
 *
 * @author Karol
 * TODO : make encryption and decryption of messages
 */
public class TTPEntity {
    
    public enum algorithms {DES, DESede, AES};
    public enum modes {CBC, ECB};
    
    /**
     * Secret key that both parties agreed upon.
     */
    private SecretKey sk;
    
    /**
     * Distributed key used for encrypting or decrypting 
     * the secret key used for communication. 
     * Currently only AES key. 
     */
    private SecretKey distrKey;
    
    /**
     * Generated session key. Alice's key.
     */
    private SecretKey generatedKey;
    
    /**
     * Decrypted session key. Bob's key.
     */
    private SecretKey decryptedKey;
    
    /**
     * Final session key agreed on by two entities, 
     * used for encryption and decryption of communication.
     */
    private SecretKey sessionKey;
    
    /**
     * Create an instance of TTPEntity with the algorithm and mode
     * for decrypting and encrypting of messages - communication between
     * this and another TTPEntity instance.
     * 
     * @param algorithm 
     * @param mode 
     */
    public TTPEntity(algorithms algorithm, modes mode) {
        
    }
    
    /**
     * To be used only with creating TTP instance.
     * @param key
     */
    protected void setDistrKey(SecretKey key) {
        distrKey = key;
    }
    
    
    public void generateSessionKey() {
        
    }
    
    
    public SecretKey generateKey(String algorithm) {
        
    }
    
    
    
    
    
}
