/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Karol
 */
public class TTP {
    
    /**
     * Alice AES key. 
     * Used for decrypting the encrypted session key received from Alice.
     */
    private SecretKey aliceKey;
    
    /**
     * Bob AES key. 
     * Used for ecnrypting the session key, before sending to Bob.
     */
    private SecretKey bobKey;
    
    /**
     * Session key used for encryption of messages.
     * This key can be any Cipher key.
     */
    private SecretKey sessionKey;
    
    public TTP(TTPEntity Alice, TTPEntity Bob) {
        Alice.setDistrKey(aliceKey = generateKey());
        Bob.setDistrKey(bobKey = generateKey());
    }
    
    public void decryptSessionKey(byte[] ciphertext, IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aliceKey, iv);
        byte[] sessionKeyByte = cipher.doFinal(ciphertext);
        sessionKey = new SecretKeySpec(sessionKeyByte, "AES");
    }
    
    public byte[] encryptSessionKey(IvParameterSpec iv) throws 
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, bobKey, iv);
        byte[] cipherByte = cipher.doFinal(sessionKey.getEncoded());
        return cipherByte;
    }
    
    /**
     * Generates AES256 key used for encryptiong of secret key.
     * This is key generated for both Alice and Bob, separately.
     * 
     * @return 
     */
    private SecretKey generateKey() {
        SecureRandom random = new SecureRandom();
        byte[] key = new byte[256 / 8];
        random.nextBytes(key);
        SecretKey sk = new SecretKeySpec(key, "AES");
        return sk;
    }
    
    public static void main(String[] args) {
        TTPEntity Alice = new TTPEntity();
        TTPEntity Bob = new TTPEntity();
        TTP ttp = new TTP(Alice, Bob);
        
        
    }
    
}
