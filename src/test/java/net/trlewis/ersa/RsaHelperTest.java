package net.trlewis.ersa;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.*;

public class RsaHelperTest {

    //region Message encryption

    @Test
    public void decryptWithGoodKey() {
        final String testMessage = "awdawd THIS IS a TEST message!!! !@$#*)@#%& [] ,.,.<> yep";
        KeyPair kp = RsaHelper.generateKeyPair();
        assert kp != null;

        byte[] encryptedMessage = new byte[1];
        try {
            encryptedMessage = RsaHelper.encryptMessage(testMessage, kp.getPublic());
        } catch(InvalidKeyException e) {
            fail("encryption key is invalid, message: " + e.getMessage());
        }

        String decrypted = null;
        try {
            decrypted = RsaHelper.decryptMessage(encryptedMessage, kp.getPrivate());
        } catch (InvalidKeyException e) {
            fail("decryption key is invalid, message: " + e.getMessage());
        }

        assertNotNull("decrypted message should not be null", decrypted);
        assertEquals("decrypted message is different", testMessage, decrypted);
    }

    @Test
    public void decryptWithBadKey() {
        final String testMessage = "TEST MESSAGE BLAH STUFF !!14834#$&(%@(";
        KeyPair kp1 = RsaHelper.generateKeyPair();
        assert kp1 != null;
        KeyPair kp2 = RsaHelper.generateKeyPair(); //so unlikely they'll be the same...
        assert kp2 != null;

        byte[] encryptedMessage = new byte[1];
        try {
            encryptedMessage = RsaHelper.encryptMessage(testMessage, kp1.getPublic());
        } catch (InvalidKeyException e) {
            fail("encryption key is invalid, message: " + e.getMessage());
        }

        boolean hadKeyException = false;
        try {
            RsaHelper.decryptMessage(encryptedMessage, kp2.getPrivate());
        } catch (InvalidKeyException e) {
            hadKeyException = true;
        }

        assertTrue("Should fail decrypting; wrong key", hadKeyException);
    }

    //endregion Message encryption

    //region Base 36 key conversion

    @Test
    public void publicBase36Good(){
        KeyPair kp = RsaHelper.generateKeyPair();
        assert kp != null;
        String encPub = RsaHelper.convertKeyToBase36(kp.getPublic());

        PublicKey pubKey = null;
        try {
            pubKey = RsaHelper.convertBase36ToPublic(encPub);
        } catch (InvalidKeySpecException e) {
            fail("Should have converted base 36 to public key");
        }

        assertTrue("keys should be equal", kp.getPublic().equals(pubKey));
    }

    @Test
    public void publicBase36Bad() {
        KeyPair kp = RsaHelper.generateKeyPair();
        assert kp != null;
        String encPub = RsaHelper.convertKeyToBase36(kp.getPublic());
        encPub += "0some0extra0base360characters0to0make0it0fail";

        boolean hadException = false;
        try {
            RsaHelper.convertBase36ToPublic(encPub);
        } catch (InvalidKeySpecException e) {
            hadException = true;
        }

        assertTrue("Base36 to public should have failed", hadException);
    }

    @Test
    public void privateBase36Good() {
        KeyPair kp = RsaHelper.generateKeyPair();
        assert kp != null;
        String encPri = RsaHelper.convertKeyToBase36(kp.getPrivate());

        PrivateKey privKey = null;
        try {
            privKey = RsaHelper.convertBase36ToPrivate(encPri);
        } catch (InvalidKeySpecException e) {
            fail("Should have converted base 36 to private key");
        }

        assertTrue("private keys should be equal", kp.getPrivate().equals(privKey));
    }

    @Test
    public void privateBase36Bad() {
        KeyPair kp = RsaHelper.generateKeyPair();
        assert kp != null;
        String encPriv = RsaHelper.convertKeyToBase36(kp.getPrivate());
        encPriv += "0more0chars0to0mess0the0private0one0up0too";

        boolean hadException = false;
        try{
            RsaHelper.convertBase36ToPrivate(encPriv);
        } catch (InvalidKeySpecException e) {
            hadException = true;
        }

        assertTrue("Base36 to private should have failed", hadException);
    }

    //endregion Base 36 key conversion
}
