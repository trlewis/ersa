package net.trlewis.ersa;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Class to manage a keystore for RSA 1024 keys. Keeps track of private keypairs
 * as well as a public-key-only list. 
 * @author travisl
 */
public class RsaKeyStore  {
	/** Added into RsaKeyStores that are saved, used to verify proper decryption when loading an RsaKeyStore */
	public static final String CHECK_VALUE = "1nv9ah5s5bsy5rrnoc3gw5rhfh9xcrrykc9b2wityhl8ve0ds4sfxms17lbpfqqctir5abgzyu5to8yhn4q07fjc58k1qlw5g2jvc3ger5zgt6ps51spdqymbd896yz2drq9o7er4e4xx3u3116rez8bnszganmo1smmtxflj8oilq1j7bt3k7menmjdk3xhctgtynr2mcwibdn37hya5q0oazjejfef81zsm4ht3vpetwen6wfcreoc3qzf8saw50bm7joun25mfuioho0nytcc3xz32qsd1zeg8foihhcjpyp4rk3dvohylutq4dxqnzcv0gk2stgbkv83ab48b9g8pqpeextln4qwqon56bv5t00gwb7kzm4oshyunsnvjwhjas10h5o6jgfq6ojxg68yv3zg3vyqezhb5b4pm4xdb8q9w2vqsytcrnvkdj5aon197l76l579svebnfglv5sul2g0h6mw2e0w8vtcfghm0z2tqa7n48u2ngkz9uk6sng2qgpi5j6mqzv1genwwejy3jiqtlq1wni44c6m01qscpqqttjms554nqloqp854f83q4kgb44kciet6g0y51ala7megliht52a65kxz89xjw0pyi7m8j7iyq3toedaf2ll73d403q4orljm6u4ms2lsha2qd1kd38b6skwjngmqi1qqvy1z62g8vh9oy5xvc6xbwtdbao3w0eozv5i4i8unjglpfeet9tch3u0s4h2wtju7yle1vei5bsk6yrq5zuifgfdz8oo8npnkgmbuxh702pstgl1j7rgb6t9bpcggfe31opxc3p8a4y47fpy3xazpkrujlrr7prw7jvm5oqm3blzeb69l1b8l78gdyxcxzlb6xwxvo0iha3wfpfz9xs0ugff5vqbx96hd0c4rn7qfgp0p88umzvcax127pn6q7aip677f5o0x7u3xwdhv4ldmekki136834cp0vn34i";

	/** Used to separate name/private/public when saving the keystore out.
	 * Also used to parse saved keys. Cannot be part of a key's name! */
	public static final char SEPERATOR = '~';

	private Map<String, KeyPair> myKeys = new HashMap<String, KeyPair>();
	private Map<String, PublicKey> myOtherKeys = new HashMap<String, PublicKey>();
	
	public RsaKeyStore() {}
	
	/**
	 * Parses the given key string and fills the KeyStore
	 * @param keyString A string representation of the key store previously retrieved from toString()
	 * @param password The password used to encrypt/decrypt the keystore
	 */
	public RsaKeyStore(final String fileName, final String password) throws InvalidKeyException {
		//TODO: delete this, just use the reader class
	}
	
	public boolean createNewMyKeyPair(final String name) {
		if(name == null || name.isEmpty() || this.myKeys.containsKey(name))
			return false;

		KeyPair kp = RsaHelper.generateKeyPair();
		this.myKeys.put(name, kp);
		return true;
	}
		
	public boolean addOtherKey(final String name, final PublicKey key) {
		if(key == null || name == null || name.isEmpty() || this.myOtherKeys.containsKey(name))
			return false;

		this.myOtherKeys.put(name, key);
		return true;
	}
	
	public Set<String> getMyKeyNames() {
		return this.myKeys.keySet();
	}
	
	public KeyPair getMyKeyPair(final String name) {
		if(name == null || name.isEmpty() || !this.myKeys.containsKey(name))
			return null;

		return this.myKeys.get(name);
	}
	 
	public Set<String> getOtherKeyNames() {
		return this.myOtherKeys.keySet();
	}
	
	public void removeMyKey(final String name) {
		if(name == null || name.isEmpty() || !this.myKeys.containsKey(name))
			return;

		this.myKeys.remove(name);
	}
		
	public void removeOtherKey(final String name) {
		if(name == null || name.isEmpty() || !this.myOtherKeys.containsKey(name))
			return;

		this.myOtherKeys.remove(name);
	}
	
	/**
	 * @param name
	 * @return
	 */
	public PublicKey getOtherKey(final String name) {
		if(name == null || name.isEmpty() || !this.myOtherKeys.containsKey(name))
			return null;

		return this.myOtherKeys.get(name);
	}
}
