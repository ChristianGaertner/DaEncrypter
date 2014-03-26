package io.github.christiangaertner.daencrypter;

/**
 *
 * @author Christian
 */
public interface Crypter extends Decrypter, Encrypter {
    
    public void setKey(String key) throws Exception;
    
    public String getID();
    
    public boolean symmetric();
    
}
