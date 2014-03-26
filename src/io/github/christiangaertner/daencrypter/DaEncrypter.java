package io.github.christiangaertner.daencrypter;

import io.github.christiangaertner.daencrypter.algorithms.Caesar;
import io.github.christiangaertner.daencrypter.algorithms.RSA;
import io.github.christiangaertner.daencrypter.algorithms.TEA;
import io.github.christiangaertner.daencrypter.gui.UIMain;
import java.math.BigInteger;
import javax.swing.JOptionPane;

/**
 *
 * @author Christian
 */
public class DaEncrypter {

    public static String plainText = "Ich bin eine geheime Nachricht!";
    protected static String[] algorithms = new String[]{"Caesar", "TEA", "RSA"};
    protected static String key = "4";
    protected static Crypter c;

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        UIMain ui = new UIMain();
        ui.setVisible(true);
        c = new Caesar();
    }

    public static String decrypt(String string, String algo) {

        if (!c.getID().equalsIgnoreCase(algo)) {
            updateC(algo);
        }

        try {
            c.setKey(key);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "This key is not valid.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
        }

        return c.decrypt(string);
    }

    public static String encrypt(String string, String algo) {

        if (!c.getID().equalsIgnoreCase(algo)) {
            updateC(algo);
        }

        try {
            c.setKey(key);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "This key is not valid.", "Invalid Key", JOptionPane.ERROR_MESSAGE);
        }



        return c.encrypt(string);
    }

    public static void setKey(String k) {
        key = k;
    }

    public static String[] getAlgorithms() {
        return algorithms;
    }

    public static void updateC(String algo) {

        if (algo.equalsIgnoreCase("Caesar")) {
            c = new Caesar();
        }
        else if(algo.equalsIgnoreCase("RSA")) {
            c = new RSA(1024);
        }
        else if(algo.equalsIgnoreCase("TEA")) {
            c = new TEA();
        }

    }
    
    public static boolean symmetric() {
        if (c == null) return true;
        return c.symmetric();
    }

    public static void runCaesar() {

        Caesar c = new Caesar();
        c.setKey(4);



        String cipherText = c.encrypt(plainText);
        System.out.println("Your Plain  Text :" + plainText);
        System.out.println("Your Cipher Text :" + cipherText);

        String cPlainText = c.decrypt(cipherText);
        System.out.println("Your Plain Text  :" + cPlainText);
    }

    public static void runRSA() {
        RSA rsa = new RSA(1024);

        BigInteger plainTextBytes = new BigInteger(plainText.getBytes());


        String cipherText = rsa.encrypt(plainText);
        System.out.println("Your Plain  Text :" + plainText);
        System.out.println("Your Cipher Text :" + cipherText);

        String cPlainText = rsa.decrypt(cipherText);
        System.out.println("Your Plain Text  :" + cPlainText);
    }
}
