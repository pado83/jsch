/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2012-2018 ymnk, JCraft,Inc. All rights reserved.

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

import java.util.Vector;

public interface IdentityRepository {

	public static final int UNAVAILABLE = 0;
	public static final int NOTRUNNING = 1;
	public static final int RUNNING = 2;

	public String getName();

	public int getStatus();

	public Vector<Identity> getIdentities();

	public boolean add(byte[] identity);

	public boolean remove(byte[] blob);

	public void removeAll();

	/**
	 * JSch will accept ciphered keys, but some implementations of
	 * IdentityRepository can not. For example, IdentityRepository for
	 * ssh-agent and pageant only accept plain keys. The following class has
	 * been introduced to cache ciphered keys for them, and pass them
	 * whenever they are de-ciphered.
	 */
	static class Wrapper implements IdentityRepository {

		private final IdentityRepository ir;
		private final Vector<Identity> cache = new Vector<Identity>();
		private boolean keep_in_cache = false;

		Wrapper(final IdentityRepository ir) {
			this(ir, false);
		}

		Wrapper(final IdentityRepository ir, final boolean keep_in_cache) {
			this.ir = ir;
			this.keep_in_cache = keep_in_cache;
		}

		@Override
		public String getName() {
			return this.ir.getName();
		}

		@Override
		public int getStatus() {
			return this.ir.getStatus();
		}

		@Override
		public boolean add(final byte[] identity) {
			return this.ir.add(identity);
		}

		@Override
		public boolean remove(final byte[] blob) {
			return this.ir.remove(blob);
		}

		@Override
		public void removeAll() {
			this.cache.removeAllElements();
			this.ir.removeAll();
		}

		@Override
		public Vector<Identity> getIdentities() {
			final Vector<Identity> result = new Vector<Identity>();
			for (int i = 0; i < this.cache.size(); i++) {
				final Identity identity = (this.cache.elementAt(i));
				result.add(identity);
			}
			final Vector<Identity> tmp = this.ir.getIdentities();
			for (int i = 0; i < tmp.size(); i++) {
				result.add(tmp.elementAt(i));
			}
			return result;
		}

		void add(final Identity identity) {
			if (!this.keep_in_cache &&
					!identity.isEncrypted() && (identity instanceof IdentityFile)) {
				try {
					this.ir.add(((IdentityFile) identity).getKeyPair().forSSHAgent());
				} catch (final JSchException e) {
					// an exception will not be thrown.
				}
			} else {
				this.cache.addElement(identity);
			}
		}

		void check() {
			if (this.cache.size() > 0) {
				final Object[] identities = this.cache.toArray();
				for (int i = 0; i < identities.length; i++) {
					final Identity identity = (Identity) (identities[i]);
					this.cache.removeElement(identity);
					add(identity);
				}
			}
		}
	}
}
