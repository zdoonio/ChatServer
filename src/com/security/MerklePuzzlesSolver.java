package com.security;

import com.utils.ArrayUtils;
import com.utils.FileUtils;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;

/**
 *
 * @author Karol
 */
public class MerklePuzzlesSolver {
    
    private final MerklePuzzles merklePuzzle;
    
    public MerklePuzzlesSolver(MerklePuzzles mp) {
        merklePuzzle = mp;
    }
    
    public byte[] solve(ArrayList<byte[]> puzzles) {
        int puzzleNumber = chooseRandomPuzzle(puzzles.size());
        byte[] puzzle = puzzles.get(puzzleNumber);
        byte[] solved = solve(puzzle);
        return solved;
    }
    
    
    public byte[] solve(String filename) {
        
        try {
            File file = new File(filename);
            int puzzleNumber = chooseRandomPuzzle(
                    FileUtils.countLines(file));
            byte[] puzzle = parsePuzzle(file, puzzleNumber);
            byte[] solved = solve(puzzle);
            return solved;
        } catch (IOException ex) {
            Logger.getLogger(MerklePuzzlesSolver.class.getName())
                    .log(Level.SEVERE, null, ex);
        }
        
        return null;
    }
    
    private byte[] solve(byte[] puzzle) {
        String prefix = merklePuzzle.getPrefix();
        int prefixLen = prefix.length();
        boolean isSolved = false;
        byte[] publicKey;
        String decryption = null;
        while(!isSolved) {
            try {
                SecretKey key = merklePuzzle.randomEncKey();
                decryption = merklePuzzle.decrypt(key, puzzle);
                isSolved = isSolved(decryption, prefix);
                
            } catch (InvalidKeyException ex) {
                isSolved = false;
            } catch (IllegalBlockSizeException ex) {
                isSolved = false;
            } catch (BadPaddingException ex) {
                isSolved = false;
            } catch (UnsupportedEncodingException ex) {
                isSolved = false;
            }
        }
        
        publicKey = solve(decryption, prefixLen).getBytes();
        
        return publicKey == null ? null : publicKey;
    }
    
    private boolean isSolved(String decryption, String prefix) {
        boolean isSolved = false;
        String decPrefix = decryption.substring(0, prefix.length());
        if(decPrefix.equals(prefix)) isSolved = true;
        return isSolved;
    }
    
    private String solve(String decryption, int prefixLen) {
        if(decryption == null) return null;
        int decLen = decryption.length();
        int publicKeyLen = (decLen - prefixLen) / 2;
        String publicKey = decryption
                .substring(publicKeyLen + prefixLen, decLen);
        System.out.println(publicKey);
        return publicKey;
    } 
    
    
    public byte[] parsePuzzle(File file, int puzzleNumber) {
        String line = FileUtils.getLine(file.getName(), puzzleNumber);
        byte[] puzzle = ArrayUtils.parseBytes(line);
        return puzzle;
    }
    
    public int chooseRandomPuzzle(int numberOfPuzzles) {
        Random random = new Random();
        // return random.nextInt(numberOfPuzzles);
        return 0;
    }
    
    public static void main(String[] args) {
        
            MerklePuzzles mp = new MerklePuzzles(MerklePuzzles.algorithms.AES);
            SecretKey sk = mp.randomEncKey();
            mp.puzzles(sk, 10000, null);
            
            MerklePuzzlesSolver mps = new MerklePuzzlesSolver(mp);
            
            mps.solve("puzzles.txt");

    }
    
    
    
    
    
    
}
