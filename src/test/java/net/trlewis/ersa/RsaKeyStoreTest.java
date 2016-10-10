package net.trlewis.ersa;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Set;

import org.junit.Test;

public class RsaKeyStoreTest {
//	@Test
//	public void test() {
//		fail("Not yet implemented");
//	}
	
	//////////////////////////////////
	//MY KEYS	
	//////////////////////////////////

	@Test
	public void addNullMyKeyPair() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = null;
		boolean r1 = ks.addMyKeyPair("some valid name", kp);
		assertFalse("Should not have added the keypair: null keypair", r1);
	}
	
	@Test
	public void addMyKeyPairNullName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		boolean r1 = ks.addMyKeyPair(null, kp);
		assertFalse("Should not have added the keypair: null name", r1);
	}
	
	@Test
	public void addMyKeyPairEmptyName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		boolean r = ks.addMyKeyPair("", kp);
		assertFalse("Should not have added the keypair: empty name", r);
	}
	
	@Test
	public void addMyKeyPairInvalidName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		boolean r = ks.addMyKeyPair("invalid~tilde", kp);
		assertFalse("Should not have added the keypair: invalid name", r);
	}
	
	@Test
	public void addMyKeyPairDuplicateName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		KeyPair kpp = RsaHelper.generateKeyPair();
		boolean r = ks.addMyKeyPair("dupe name blah", kp);
		boolean rr = ks.addMyKeyPair("dupe name blah", kpp);
		assertTrue("Should have added first keypair", r);
		assertFalse("Should not have added second keypair: duplicate name", rr);
	}
	
	@Test
	public void createNewMyKeys() {
		//only testing the return value of the method here.
		RsaKeyStore ks = new RsaKeyStore();
		boolean r1 = ks.createNewMyKeyPair("newkp");
		boolean r2 = ks.createNewMyKeyPair("newtwo");
		assertTrue("Should have added the key", r1);
		assertTrue("Should have added the second key", r2);
	}

	@Test
	public void createNewMyKeyDuplicateName() {
		RsaKeyStore ks = new RsaKeyStore();
		assertTrue("should have created key", ks.createNewMyKeyPair("same"));
		assertFalse("should not have created key", ks.createNewMyKeyPair("same"));
	}
	
	@Test
	public void createNewMyKeyEmptyName() {
		//should require a name
		RsaKeyStore ks = new RsaKeyStore();
		boolean re = ks.createNewMyKeyPair("");
		assertFalse("Should not have created new my keypair: empty name", re);
	}	
	@Test
	public void createNewMyKeyInvalidName() {
		RsaKeyStore ks = new RsaKeyStore();
		boolean r = ks.createNewMyKeyPair("invalid~name~because~~tilde");
		assertFalse("Should not have created keypair: invalid name", r);
		//fail("Not yet implemented");
	}
	
	@Test
	public void createNewMyKeyNullName() {
		RsaKeyStore ks = new RsaKeyStore();
		boolean re = ks.createNewMyKeyPair(null);
		assertFalse("Should not have created new my keypair: null name", re);
	}
	
	@Test
	public void removeMyKey() {
		//remove the only key from a keystore
		RsaKeyStore ks = new RsaKeyStore();
		final String keyName = "testkey";
		ks.createNewMyKeyPair(keyName);
		ks.removeMyKey(keyName);
		KeyPair kp = ks.getMyKeyPair(keyName);
		assertNull("keypair should have been removed", kp);
	}
		
	@Test
	public void removeMyKeyNotThere() {
		//remove a key that does NOT exist
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("one");
		ks.createNewMyKeyPair("two");
		ks.removeMyKey("three");
		Set<String> names = ks.getMyKeyNames();
		assertTrue("wrong number of keys", names.size() == 2);
		assertTrue("should contain key", names.contains("one"));
		assertTrue("should contain key", names.contains("two"));
		assertFalse("should not contain key", names.contains("three"));
	}
	
	@Test
	public void removeMyKeyNullName() {
		//don't provide a name for the key to remove
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("first");
		ks.createNewMyKeyPair("second");
		ks.removeMyKey(null);
		Set<String> names =  ks.getMyKeyNames();
		assertTrue("wrong number of keys", names.size() == 2);
		assertTrue("should contain key", names.contains("first"));
		assertTrue("should contain key", names.contains("second"));
		assertFalse("should not contain key", names.contains(null));
	}
	
	@Test
	public void removeOneOfMyKeys() {
		//remove one key from a keystore that has multiple
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("uno");
		ks.createNewMyKeyPair("dos");
		ks.removeMyKey("uno");
		Set<String> names = ks.getMyKeyNames();
		assertTrue("wrong number of keys", names.size() == 1);
		assertFalse("should not contain key", names.contains("uno"));
		assertTrue("should contain key", names.contains("dos"));
	}
	
	@Test
	public void getMyKeyPairs() {
		//check that all the pairs entered are gettable 
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("ichi");
		ks.createNewMyKeyPair("ni");
		KeyPair kp = ks.getMyKeyPair("ichi");
		assertNotNull("should have returned keypair", kp);
		KeyPair kpp = ks.getMyKeyPair("ni");
		assertNotNull("should have returned keypair", kpp);
	}
	
	@Test
	public void getMyKeyPairsNoName() {
		//try to fetch a key with an empty string or null name
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("the only one");
		KeyPair kp = ks.getMyKeyPair("blah");
		assertNull("should have returned null", kp);
	}
	
	@Test
	public void getMyKeyNames() {
		//make sure the list of key names has only the ones it should
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("never");
		ks.createNewMyKeyPair("gonna");
		ks.createNewMyKeyPair("give");
		ks.createNewMyKeyPair("you");
		ks.createNewMyKeyPair("up");
		Set<String> names = ks.getMyKeyNames();
		assertTrue("incorrect number of names", names.size() == 5);
		assertTrue("should contain name", names.contains("never"));
		assertTrue("should contain name", names.contains("gonna"));
		assertTrue("should contain name", names.contains("give"));
		assertTrue("should contain name", names.contains("you"));
		assertTrue("should contain name", names.contains("up"));
	}
	
	//////////////////////////////////
	//OTHER KEYS
	//////////////////////////////////
	
	@Test
	public void addOtherKeys() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		assertTrue("should have added key", ks.addOtherKey("firstOther", kp.getPublic()));
		KeyPair kpp = RsaHelper.generateKeyPair();
		assertTrue("should have added key", ks.addOtherKey("secondOther", kpp.getPublic()));
	}
	
	@Test
	public void addOtherKeyDuplicateName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		assertTrue("should have added other key", ks.addOtherKey("sameOther", kp.getPublic()));
		KeyPair kpp = RsaHelper.generateKeyPair();
		assertFalse("should not have added other key", ks.addOtherKey("sameOther", kpp.getPublic()));
	}
	
	@Test
	public void addOtherKeyInvalidName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		boolean r = ks.addOtherKey("bad~tilde~chars", kp.getPublic());
		assertFalse("Should not have added other key: invalid name", r);
	}

	@Test
	public void addOtherKeyNoName() {
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		assertFalse("should not have added other key", ks.addOtherKey("", kp.getPublic()));
		KeyPair kpp = RsaHelper.generateKeyPair();
		assertFalse("should not have added other key", ks.addOtherKey(null, kpp.getPublic()));
	}
	
	@Test
	public void addOtherNullKey() {
		RsaKeyStore ks = new RsaKeyStore();
		assertFalse("should not add null key", ks.addOtherKey("some name", null));
	}
	
	@Test
	public void getOtherKeys() {
		//make sure other keys inserted are same returned
		RsaKeyStore ks = new RsaKeyStore();
		KeyPair kp = RsaHelper.generateKeyPair();
		ks.addOtherKey("first other one", kp.getPublic());
		KeyPair kpp = RsaHelper.generateKeyPair();
		ks.addOtherKey("second other one", kpp.getPublic());
		PublicKey pk = ks.getOtherKey("first other one");
		assertTrue("should be same key", kp.getPublic().equals(pk));
		PublicKey ppk = ks.getOtherKey("second other one");
		assertTrue("should be same key", kpp.getPublic().equals(ppk));
	}
	
	@Test
	public void getOtherKeyNames() {
		RsaKeyStore ks = new RsaKeyStore();
		ks.addOtherKey("one other test", RsaHelper.generateKeyPair().getPublic());
		ks.addOtherKey("two other test", RsaHelper.generateKeyPair().getPublic());
		Set<String> names = ks.getOtherKeyNames();
		assertTrue("wrong number of keys", names.size() == 2);
		assertTrue("should contain key", names.contains("one other test"));
		assertTrue("should contain key", names.contains("two other test"));
	}
	
	@Test
	public void removeOtherKey() {
		RsaKeyStore ks = new RsaKeyStore();
		ks.addOtherKey("other uno", RsaHelper.generateKeyPair().getPublic());
		ks.removeOtherKey("other uno");
		PublicKey pk = ks.getOtherKey("other uno");
		assertNull("other key should have been removed", pk);
	}
	
	@Test
	public void removeOtherKeyNoName() {
		RsaKeyStore ks = new RsaKeyStore();
		ks.addOtherKey("other first blah", RsaHelper.generateKeyPair().getPublic());
		ks.removeOtherKey("");
		PublicKey pk = ks.getOtherKey("other first blah");
		assertNotNull("key should still exist", pk);
	}
	
	@Test
	public void removeOtherKeyNotThere() {
		RsaKeyStore ks = new RsaKeyStore();
		ks.addOtherKey("other remain", RsaHelper.generateKeyPair().getPublic());
		ks.removeOtherKey("some other name");
		PublicKey pk = ks.getOtherKey("other remain");
		assertNotNull("should still be there", pk);
	}

}
