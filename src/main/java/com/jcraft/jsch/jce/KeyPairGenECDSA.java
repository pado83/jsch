/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.

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

package com.jcraft.jsch.jce;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import com.jcraft.jsch.JSchException;

public class KeyPairGenECDSA implements com.jcraft.jsch.KeyPairGenECDSA {

	byte[] d;
	byte[] r;
	byte[] s;
	ECPublicKey pubKey;
	ECPrivateKey prvKey;
	ECParameterSpec params;

	@Override
	public void init(final int key_size) throws Exception {
		String name = null;
		if (key_size == 256) {
			name = "secp256r1";
		} else if (key_size == 384) {
			name = "secp384r1";
		} else if (key_size == 521) {
			name = "secp521r1";
		} else {
			throw new JSchException("unsupported key size: " + key_size);
		}

		for (int i = 0; i < 1000; i++) {
			final KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
			final ECGenParameterSpec ecsp = new ECGenParameterSpec(name);
			kpg.initialize(ecsp);
			final KeyPair kp = kpg.genKeyPair();
			this.prvKey = (ECPrivateKey) kp.getPrivate();
			this.pubKey = (ECPublicKey) kp.getPublic();
			this.params = this.pubKey.getParams();
			this.d = this.prvKey.getS().toByteArray();
			final ECPoint w = this.pubKey.getW();
			this.r = w.getAffineX().toByteArray();
			this.s = w.getAffineY().toByteArray();

			if (this.r.length != this.s.length) {
				continue;
			}
			if (key_size == 256 && this.r.length == 32) {
				break;
			}
			if (key_size == 384 && this.r.length == 48) {
				break;
			}
			if (key_size == 521 && this.r.length == 66) {
				break;
			}
		}
		if (this.d.length < this.r.length) {
			this.d = KeyPairGenECDSA.insert0(this.d);
		}
	}

	@Override
	public byte[] getD() {
		return this.d;
	}

	@Override
	public byte[] getR() {
		return this.r;
	}

	@Override
	public byte[] getS() {
		return this.s;
	}

	ECPublicKey getPublicKey() {
		return this.pubKey;
	}

	ECPrivateKey getPrivateKey() {
		return this.prvKey;
	}

	private static byte[] insert0(final byte[] buf) {
		// if ((buf[0] & 0x80) == 0) return buf;
		final byte[] tmp = new byte[buf.length + 1];
		System.arraycopy(buf, 0, tmp, 1, buf.length);
		bzero(buf);
		return tmp;
	}

	private static byte[] chop0(final byte[] buf) {
		if (buf[0] != 0 || (buf[1] & 0x80) == 0) {
			return buf;
		}
		final byte[] tmp = new byte[buf.length - 1];
		System.arraycopy(buf, 1, tmp, 0, tmp.length);
		bzero(buf);
		return tmp;
	}

	private static void bzero(final byte[] buf) {
		for (int i = 0; i < buf.length; i++) {
			buf[i] = 0;
		}
	}
}
