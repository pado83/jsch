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

class LocalIdentityRepository implements IdentityRepository {

	private static final String name = "Local Identity Repository";

	private final Vector<Identity> identities = new Vector<Identity>();
	private final JSch jsch;

	LocalIdentityRepository(final JSch jsch) {
		this.jsch = jsch;
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getStatus() {
		return RUNNING;
	}

	@Override
	public synchronized Vector<Identity> getIdentities() {
		this.removeDupulicates();
		final Vector<Identity> v = new Vector<Identity>();
		for (int i = 0; i < this.identities.size(); i++) {
			v.addElement(this.identities.elementAt(i));
		}
		return v;
	}

	public synchronized void add(final Identity identity) {
		if (!this.identities.contains(identity)) {
			final byte[] blob1 = identity.getPublicKeyBlob();
			if (blob1 == null) {
				this.identities.addElement(identity);
				return;
			}
			for (int i = 0; i < this.identities.size(); i++) {
				final byte[] blob2 = this.identities.elementAt(i).getPublicKeyBlob();
				if (blob2 != null && Util.array_equals(blob1, blob2)) {
					if (!identity.isEncrypted() &&
							this.identities.elementAt(i).isEncrypted()) {
						this.remove(blob2);
					} else {
						return;
					}
				}
			}
			this.identities.addElement(identity);
		}
	}

	@Override
	public synchronized boolean add(final byte[] identity) {
		try {
			final Identity _identity = IdentityFile.newInstance("from remote:", identity, null, this.jsch);
			this.add(_identity);
			return true;
		} catch (final JSchException e) {
			return false;
		}
	}

	synchronized void remove(final Identity identity) {
		if (this.identities.contains(identity)) {
			this.identities.removeElement(identity);
			identity.clear();
		} else {
			this.remove(identity.getPublicKeyBlob());
		}
	}

	@Override
	public synchronized boolean remove(final byte[] blob) {
		if (blob == null) {
			return false;
		}
		for (int i = 0; i < this.identities.size(); i++) {
			final Identity _identity = (this.identities.elementAt(i));
			final byte[] _blob = _identity.getPublicKeyBlob();
			if (_blob == null || !Util.array_equals(blob, _blob)) {
				continue;
			}
			this.identities.removeElement(_identity);
			_identity.clear();
			return true;
		}
		return false;
	}

	@Override
	public synchronized void removeAll() {
		for (int i = 0; i < this.identities.size(); i++) {
			final Identity identity = (this.identities.elementAt(i));
			identity.clear();
		}
		this.identities.removeAllElements();
	}

	private void removeDupulicates() {
		final Vector<byte[]> v = new Vector<byte[]>();
		final int len = this.identities.size();
		if (len == 0) {
			return;
		}
		for (int i = 0; i < len; i++) {
			final Identity foo = this.identities.elementAt(i);
			final byte[] foo_blob = foo.getPublicKeyBlob();
			if (foo_blob == null) {
				continue;
			}
			for (int j = i + 1; j < len; j++) {
				final Identity bar = this.identities.elementAt(j);
				final byte[] bar_blob = bar.getPublicKeyBlob();
				if (bar_blob == null) {
					continue;
				}
				if (Util.array_equals(foo_blob, bar_blob) &&
						foo.isEncrypted() == bar.isEncrypted()) {
					v.addElement(foo_blob);
					break;
				}
			}
		}
		for (int i = 0; i < v.size(); i++) {
			this.remove(v.elementAt(i));
		}
	}
}
