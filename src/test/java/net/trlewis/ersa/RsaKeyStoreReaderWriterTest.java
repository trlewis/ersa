package net.trlewis.ersa;

import static org.junit.Assert.*;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.spec.InvalidKeySpecException;
import java.text.ParseException;

public class RsaKeyStoreReaderWriterTest {

    @Test
    public void goodReadAndWrite() {
        RsaKeyStore ks = new RsaKeyStore();
        ks.createNewMyKeyPair("mine");
        KeyPair kp = RsaHelper.generateKeyPair();
        ks.addOtherKey("other", kp.getPublic());

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        try {
            RsaKeyStoreWriter.writeRsaKeyStore(ks, outStream, "super rad password");
        } catch (IOException e) {
            e.printStackTrace();
            fail("Exception writing keystore: " + e.getMessage());
        }

        byte[] outBytes = outStream.toByteArray();
        ByteArrayInputStream inStream = new ByteArrayInputStream(outBytes);
        RsaKeyStore outKs = null;
        try {
            outKs = RsaKeyStoreReader.readKeyStore(inStream, "super rad password");
        } catch (IOException | ParseException | InvalidKeySpecException e) {
            e.printStackTrace();
            fail("Exception reading keystore: " + e.getMessage());
        }

        KeyPair origKp = ks.getMyKeyPair("mine");
        KeyPair copyKp = outKs.getMyKeyPair("mine");
        assertEquals("My public keys mismatch", origKp.getPublic(), copyKp.getPublic());
        assertEquals("My private keys mismatch", origKp.getPrivate(), copyKp.getPrivate());

        assertEquals("Other key mismatch", ks.getOtherKey("other"), outKs.getOtherKey("other"));
    }

    @Test
    public void badPassword() {
        RsaKeyStore ks = new RsaKeyStore();
        ks.createNewMyKeyPair("mine");
        KeyPair kp = RsaHelper.generateKeyPair();
        ks.addOtherKey("other", kp.getPublic());

        ByteArrayOutputStream outStream = new ByteArrayOutputStream();
        try {
            RsaKeyStoreWriter.writeRsaKeyStore(ks, outStream, "good password");
        } catch (IOException e) {
            e.printStackTrace();
            fail("Exception writing keystore: " + e.getMessage());
        }

        byte[] outBytes = outStream.toByteArray();
        ByteArrayInputStream inStream = new ByteArrayInputStream(outBytes);
        boolean hadIoException = false;
        try {
            RsaKeyStoreReader.readKeyStore(inStream, "bad password");
        } catch (IOException e) {
            hadIoException = true;
        } catch (InvalidKeySpecException | ParseException e) {
            fail("Wrong exception thrown for bad password");
        }

        if(!hadIoException)
            fail("invalid password should have caused IOException");
    }
}
