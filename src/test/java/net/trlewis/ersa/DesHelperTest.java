package net.trlewis.ersa;

import static org.junit.Assert.*;
import org.junit.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

public class DesHelperTest {
    @Test
    public void decryptWithGoodPassword() {
        String testStr = "here's my test string wow12321~-=";
        byte[] bytes = DesHelper.getEncryptedBytes(testStr, "secure password here");
        String outStr = null;
        try {
            outStr = DesHelper.getDecryptedString(bytes, "secure password here");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            fail("Password is correct, should have decrypted. Message: " + e.getMessage());
        }

        assertNotNull("Decrypted message should not be null", outStr);
        assertEquals("Decrypted message is different than original", testStr, outStr);
    }

    @Test
    public void decryptWithBadPassword() {
        String testStr = "here's a message that will never be decrypted :[";
        byte[] bytes = DesHelper.getEncryptedBytes(testStr, "correct password");
        boolean exceptionEncountered = false;
        try {
            DesHelper.getDecryptedString(bytes, "incorrect password, error!");
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            exceptionEncountered = true;
        }

        assertTrue("Incorrect password should generate exception", exceptionEncountered);
    }
}
