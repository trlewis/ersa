package net.trlewis.ersa;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.Test;

public class RsaKeyStoreTest {
//	private RsaKeyStore ks;
//	
//	@Before
//	public void setUp() {
//		ks = new RsaKeyStore();
//	}

//	@Test
//	public void test() {
//		fail("Not yet implemented");
//	}
	
	@Test
	public void createNewMyKeys() {
		RsaKeyStore ks = new RsaKeyStore();
		ks.createNewMyKeyPair("newkp");
		PublicKey pubKey = ks.getMyKeyPair("newkp");
		assertNotNull("Should have found my public key", pubKey);
		
		//TODO: add more than one. don't fetch until after adding all
	}
	
	@Test
	public void createNoNameKey() {
		
	}
	
	@Test
	public void removeMyKey() {
		
	}
		
	@Test
	public void removeMyKeyNotThere() {
		
	}
	
	@Test
	public void removeMyKeyNoName() {
		
	}
	
	@Test
	public void removeOneOfMyKeys() {
		
	}
	
	@Test
	public void getMyKeyPairs() {
		
	}
	
	@Test
	public void getMyKeyPairsNoName() {
		
	}
	
	@Test
	public void getMyKeyNames() {
		
	}
	
	//OTHER KEYS
	
	@Test
	public void addOtherKeys() {
		
	}
	
	@Test
	public void addOtherKeyNoName() {
		
	}
	
	@Test
	public void addOtherNullKey() {
		
	}
	
	@Test
	public void getOtherKeys() {
		
	}
	
	@Test
	public void getOtherKeyNames() {
		
	}
	
	@Test
	public void removeOtherKey() {
		
	}
	
	@Test
	public void removeOtherKeyNoName() {
		
	}
	
	@Test
	public void removeOtherKeyNotThere() {
		
	}
}
