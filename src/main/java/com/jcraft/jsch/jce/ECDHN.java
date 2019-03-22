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

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;

import javax.crypto.KeyAgreement;

public class ECDHN implements com.jcraft.jsch.ECDH {

	byte[] Q_array;
	ECPublicKey publicKey;

	private KeyAgreement myKeyAgree;

	@Override
	public void init(final int size) throws Exception {
		this.myKeyAgree = KeyAgreement.getInstance("ECDH");
		final KeyPairGenECDSA kpair = new KeyPairGenECDSA();
		kpair.init(size);
		this.publicKey = kpair.getPublicKey();
		final byte[] r = kpair.getR();
		final byte[] s = kpair.getS();
		this.Q_array = toPoint(r, s);
		this.myKeyAgree.init(kpair.getPrivateKey());
	}

	@Override
	public byte[] getQ() throws Exception {
		return this.Q_array;
	}

	@Override
	public byte[] getSecret(final byte[] r, final byte[] s) throws Exception {

		final KeyFactory kf = KeyFactory.getInstance("EC");
		final ECPoint w = new ECPoint(new BigInteger(1, r), new BigInteger(1, s));
		final ECPublicKeySpec spec = new ECPublicKeySpec(w, this.publicKey.getParams());
		final PublicKey theirPublicKey = kf.generatePublic(spec);
		this.myKeyAgree.doPhase(theirPublicKey, true);
		return this.myKeyAgree.generateSecret();
	}

	private static BigInteger two = BigInteger.ONE.add(BigInteger.ONE);
	private static BigInteger three = two.add(BigInteger.ONE);

	// SEC 1: Elliptic Curve Cryptography, Version 2.0
	// http://www.secg.org/sec1-v2.pdf
	// 3.2.2.1 Elliptic Curve Public Key Validation Primitive
	@Override
	public boolean validate(final byte[] r, final byte[] s) throws Exception {
		final BigInteger x = new BigInteger(1, r);
		final BigInteger y = new BigInteger(1, s);

		// Step.1
		// Check that Q != O
		final ECPoint w = new ECPoint(x, y);
		if (w.equals(ECPoint.POINT_INFINITY)) {
			return false;
		}

		// Step.2
		// If T represents elliptic curve domain parameters over Fp,
		// check that xQ and yQ are integers in the interval [0, p-1],
		// and that:
		// y^2 = x^3 + x*a + b (mod p)

		final ECParameterSpec params = this.publicKey.getParams();
		final EllipticCurve curve = params.getCurve();
		final BigInteger p = ((ECFieldFp) curve.getField()).getP(); // nistp should be Fp.

		// xQ and yQ should be integers in the interval [0, p-1]
		final BigInteger p_sub1 = p.subtract(BigInteger.ONE);
		if (!(x.compareTo(p_sub1) <= 0 && y.compareTo(p_sub1) <= 0)) {
			return false;
		}

		// y^2 = x^3 + x*a + b (mod p)
		final BigInteger tmp = x.multiply(curve.getA()).add(curve.getB()).add(x.modPow(three, p)).mod(p);
		final BigInteger y_2 = y.modPow(two, p);
		if (!y_2.equals(tmp)) {
			return false;
		}

		// Step.3
		// Check that nQ = O.
		// Unfortunately, JCE does not provide the point multiplication method.
		/*
		 * if(!w.multiply(params.getOrder()).equals(ECPoint.POINT_INFINITY)){
		 * return false;
		 * }
		 */
		return true;
	}

	private static byte[] toPoint(final byte[] r_array, final byte[] s_array) {
		final byte[] tmp = new byte[1 + r_array.length + s_array.length];
		tmp[0] = 0x04;
		System.arraycopy(r_array, 0, tmp, 1, r_array.length);
		System.arraycopy(s_array, 0, tmp, 1 + r_array.length, s_array.length);
		return tmp;
	}

	private static byte[] insert0(final byte[] buf) {
		if ((buf[0] & 0x80) == 0) {
			return buf;
		}
		final byte[] tmp = new byte[buf.length + 1];
		System.arraycopy(buf, 0, tmp, 1, buf.length);
		ECDHN.bzero(buf);
		return tmp;
	}

	private static byte[] chop0(final byte[] buf) {
		if (buf[0] != 0) {
			return buf;
		}
		final byte[] tmp = new byte[buf.length - 1];
		System.arraycopy(buf, 1, tmp, 0, tmp.length);
		ECDHN.bzero(buf);
		return tmp;
	}

	private static void bzero(final byte[] buf) {
		for (int i = 0; i < buf.length; i++) {
			buf[i] = 0;
		}
	}
}
