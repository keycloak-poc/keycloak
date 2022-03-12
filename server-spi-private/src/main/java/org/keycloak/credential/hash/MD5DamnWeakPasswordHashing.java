package org.keycloak.credential.hash;


import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MD5DamnWeakPasswordHashing {

    public void hashRandomThing(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        md.update(password.getBytes());
        byte[] digest = md.digest();
        DatatypeConverter.printHexBinary(digest).toUpperCase();
    }
}
