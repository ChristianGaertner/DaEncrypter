package io.github.christiangaertner.daencrypter.algorithms;

import io.github.christiangaertner.daencrypter.Crypter;
import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *
 * @author Christian
 */
public class RSA implements Crypter {

    private BigInteger n, d, e;
    private int bitlen = 1024;

    /**
     * Create an instance that can encrypt using someone elses public key.
     */
    public RSA(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }
    
    /**
     *
     * @param key
     * @throws Exception
     */
    @Override
    public void setKey(String key) throws Exception {
//        String[] ne = key.split("|");
//        this.n = new BigInteger(ne[0].getBytes());
//        this.e = new BigInteger(ne[1].getBytes());
    }

    /**
     * Create an instance that can both encrypt and decrypt.
     */
    public RSA(int bits) {
        bitlen = bits;
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }

    @Override
    /**
     * Encrypt the given plaintext message.
     */
    public synchronized String encrypt(String message) {
        return (new BigInteger(message.getBytes())).modPow(e, n).toString();
    }

    /**
     * Encrypt the given plaintext message.
     */
    public synchronized BigInteger encrypt(BigInteger message) {
        return message.modPow(e, n);
    }

    /**
     * Decrypt the given ciphertext message.
     */
    @Override
    public synchronized String decrypt(String message) {
        return new String((new BigInteger(message)).modPow(d, n).toByteArray());
    }

    /**
     * Decrypt the given ciphertext message.
     */
    public synchronized BigInteger decrypt(BigInteger message) {
        return message.modPow(d, n);
    }

    /**
     * Generate a new public and private key set.
     */
    public synchronized void generateKeys() {
        SecureRandom r = new SecureRandom();
        BigInteger p = new BigInteger(bitlen / 2, 100, r);
        BigInteger q = new BigInteger(bitlen / 2, 100, r);
        n = p.multiply(q);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q
                .subtract(BigInteger.ONE));
        e = new BigInteger("3");
        while (m.gcd(e).intValue() > 1) {
            e = e.add(new BigInteger("2"));
        }
        d = e.modInverse(m);
    }
    
    
  /** Return the modulus. */
  public synchronized BigInteger getN() {
    return n;
  }

  /** Return the public key. */
  public synchronized BigInteger getE() {
    return e;
  }

    @Override
    public String getID() {
        return "RSA";
    }

    @Override
    public boolean symmetric() {
        return false;
    }
}
