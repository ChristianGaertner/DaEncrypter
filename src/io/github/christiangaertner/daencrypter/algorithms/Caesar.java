package io.github.christiangaertner.daencrypter.algorithms;

import io.github.christiangaertner.daencrypter.Crypter;

/**
 *
 * @author Christian
 */
public class Caesar implements Crypter {

    private int shiftKey;

    /**
     *
     * @param key
     * @throws Exception
     */
    @Override
    public void setKey(String key) throws Exception {
        this.shiftKey = Integer.parseInt(key);
    }

    public void setKey(int key) {
        this.shiftKey = key;
    }

    /**
     *
     * @param string
     * @return
     */
    @Override
    public String encrypt(String string) {
        StringBuilder sb = new StringBuilder();
        for (char c : string.toCharArray()) {
            sb.append((char) (c + shiftKey));
        }
        return sb.toString();
    }

    /**
     *
     * @param string
     * @return
     */
    @Override
    public String decrypt(String string) {
        StringBuilder sb = new StringBuilder();
        for (char c : string.toCharArray()) {
            sb.append((char) (c - shiftKey));
        }
        return sb.toString();
    }

    @Override
    public String getID() {
        return "Caesar";
    }

    @Override
    public boolean symmetric() {
        return true;
    }
}
