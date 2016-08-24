package net.trlewis.ersa;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Class to manage a keystore for RSA 1024 keys. Keeps track of private keypairs
 * as well as a public-key-only list. Has features for reading/writing the 
 * keystore to a file.
 * @author travisl
 */
public class RsaKeyStore  {
	private Map<String, KeyPair> myKeys = new HashMap<String, KeyPair>();
	private Map<String, PublicKey> myOtherKeys = new HashMap<String, PublicKey>();
	
	public RsaKeyStore() {}
	
	/**
	 * Parses the given key string and fills the KeyStore
	 * @param keyString A string representation of the key store previously retrieved from toString()
	 * @param password The password used to encrypt/decrypt the keystore
	 */
	public RsaKeyStore(final String fileName, final String password) throws InvalidKeyException {
		//TODO: read file...
	}
	
	public boolean createNewMyKeyPair(final String name) {
		if(name == null || name.length() == 0)
			return false;
		
		KeyPair kp = RsaHelper.generateKeyPair();
		this.myKeys.put(name, kp);
		return true;
	}
		
	public void addOtherKey(final String name, final PublicKey key) {
		this.myOtherKeys.put(name, key);
	}
	
	public Set<String> getMyKeyNames() {
		return this.myKeys.keySet();
	}
	
	public PublicKey getMyKeyPair(final String name) {
		return null;
	}
	 
	public Set<String> getOtherKeyNames() {
		return this.myOtherKeys.keySet();
	}
	
	public void removeMyKey(final String name) {
		
	}
		
	public void removeOtherKey(final String name) {
		if(!this.myOtherKeys.containsKey(name))
			return;
		
		PublicKey ok = this.myOtherKeys.get(name);
		this.myOtherKeys.remove(ok);
	}
	
	/**
	 * @param name
	 * @return
	 */
	public PublicKey getOtherKey(final String name) {
//		if(!this.myOtherKeys.containsKey(name))
//			return null;
		return this.myOtherKeys.get(name);
	}
	

	
	/**
	 * Used to generate the data of this keystore that will be encoded then saved
	 * @return
	 */
	private String getKeyString() {
		//TODO: generate the key string
		//use custom code or try to use some sort of library to format it as JSON or something?
		return null;
	}
}
