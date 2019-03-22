/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright 
     notice, this list of conditions and the following disclaimer in 
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package com.jcraft.jsch;

import java.io.UnsupportedEncodingException;

class IdentityFile implements Identity {

	private final JSch jsch;
	private KeyPair kpair;
	private final String identity;

	static IdentityFile newInstance(final String prvfile, final String pubfile, final JSch jsch) throws JSchException {
		final KeyPair kpair = KeyPair.load(jsch, prvfile, pubfile);
		return new IdentityFile(jsch, prvfile, kpair);
	}

	static IdentityFile newInstance(final String name, final byte[] prvkey, final byte[] pubkey, final JSch jsch) throws JSchException {

		final KeyPair kpair = KeyPair.load(jsch, prvkey, pubkey);
		return new IdentityFile(jsch, name, kpair);
	}

	private IdentityFile(final JSch jsch, final String name, final KeyPair kpair) throws JSchException {
		this.jsch = jsch;
		this.identity = name;
		this.kpair = kpair;
	}

	/**
	 * Decrypts this identity with the specified pass-phrase.
	 * 
	 * @param passphrase the pass-phrase for this identity.
	 * @return <tt>true</tt> if the decryption is succeeded
	 *         or this identity is not cyphered.
	 */
	@Override
	public boolean setPassphrase(final byte[] passphrase) throws JSchException {
		return this.kpair.decrypt(passphrase);
	}

	/**
	 * Returns the public-key blob.
	 * 
	 * @return the public-key blob
	 */
	@Override
	public byte[] getPublicKeyBlob() {
		return this.kpair.getPublicKeyBlob();
	}

	/**
	 * Signs on data with this identity, and returns the result.
	 * 
	 * @param data data to be signed
	 * @return the signature
	 */
	@Override
	public byte[] getSignature(final byte[] data) {
		return this.kpair.getSignature(data);
	}

	/**
	 * @deprecated This method should not be invoked.
	 * @see #setPassphrase(byte[] passphrase)
	 */
	@Deprecated
	@Override
	public boolean decrypt() {
		throw new RuntimeException("not implemented");
	}

	/**
	 * Returns the name of the key algorithm.
	 * 
	 * @return "ssh-rsa" or "ssh-dss"
	 */
	@Override
	public String getAlgName() {
		final byte[] name = this.kpair.getKeyTypeName();
		try {
			return new String(name, "UTF-8");
		} catch (final UnsupportedEncodingException e) {
			return new String(name);
		}
	}

	/**
	 * Returns the name of this identity.
	 * It will be useful to identify this object in the {@link IdentityRepository}.
	 */
	@Override
	public String getName() {
		return this.identity;
	}

	/**
	 * Returns <tt>true</tt> if this identity is cyphered.
	 * 
	 * @return <tt>true</tt> if this identity is cyphered.
	 */
	@Override
	public boolean isEncrypted() {
		return this.kpair.isEncrypted();
	}

	/**
	 * Disposes internally allocated data, like byte array for the private key.
	 */
	@Override
	public void clear() {
		this.kpair.dispose();
		this.kpair = null;
	}

	/**
	 * Returns an instance of {@link KeyPair} used in this {@link Identity}.
	 * 
	 * @return an instance of {@link KeyPair} used in this {@link Identity}.
	 */
	public KeyPair getKeyPair() {
		return this.kpair;
	}
}
