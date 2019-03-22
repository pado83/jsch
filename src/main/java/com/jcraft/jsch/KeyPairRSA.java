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

import java.math.BigInteger;

public class KeyPairRSA extends KeyPair {

	private byte[] n_array; // modulus p multiply q
	private byte[] pub_array; // e
	private byte[] prv_array; // d e^-1 mod (p-1)(q-1)

	private byte[] p_array; // prime p
	private byte[] q_array; // prime q
	private byte[] ep_array; // prime exponent p dmp1 == prv mod (p-1)
	private byte[] eq_array; // prime exponent q dmq1 == prv mod (q-1)
	private byte[] c_array; // coefficient iqmp == modinv(q, p) == q^-1 mod p

	private int key_size = 1024;

	public KeyPairRSA(final JSch jsch) {
		this(jsch, null, null, null);
	}

	public KeyPairRSA(final JSch jsch,
			final byte[] n_array,
			final byte[] pub_array,
			final byte[] prv_array) {
		super(jsch);
		this.n_array = n_array;
		this.pub_array = pub_array;
		this.prv_array = prv_array;
		if (n_array != null) {
			this.key_size = (new java.math.BigInteger(n_array)).bitLength();
		}
	}

	@Override
	void generate(final int key_size) throws JSchException {
		this.key_size = key_size;
		try {
			final Class<?> c = Class.forName(JSch.getConfig("keypairgen.rsa"));
			KeyPairGenRSA keypairgen = (KeyPairGenRSA) (c.newInstance());
			keypairgen.init(key_size);
			this.pub_array = keypairgen.getE();
			this.prv_array = keypairgen.getD();
			this.n_array = keypairgen.getN();

			this.p_array = keypairgen.getP();
			this.q_array = keypairgen.getQ();
			this.ep_array = keypairgen.getEP();
			this.eq_array = keypairgen.getEQ();
			this.c_array = keypairgen.getC();

			keypairgen = null;
		} catch (final Exception e) {
			// System.err.println("KeyPairRSA: "+e);
			if (e instanceof Throwable) {
				throw new JSchException(e.toString(), e);
			}
			throw new JSchException(e.toString());
		}
	}

	private static final byte[] begin = Util.str2byte("-----BEGIN RSA PRIVATE KEY-----");
	private static final byte[] end = Util.str2byte("-----END RSA PRIVATE KEY-----");

	@Override
	byte[] getBegin() {
		return begin;
	}

	@Override
	byte[] getEnd() {
		return end;
	}

	@Override
	byte[] getPrivateKey() {
		final int content = 1 + this.countLength(1) + 1 + // INTEGER
				1 + this.countLength(this.n_array.length) + this.n_array.length + // INTEGER N
				1 + this.countLength(this.pub_array.length) + this.pub_array.length + // INTEGER pub
				1 + this.countLength(this.prv_array.length) + this.prv_array.length + // INTEGER prv
				1 + this.countLength(this.p_array.length) + this.p_array.length + // INTEGER p
				1 + this.countLength(this.q_array.length) + this.q_array.length + // INTEGER q
				1 + this.countLength(this.ep_array.length) + this.ep_array.length + // INTEGER ep
				1 + this.countLength(this.eq_array.length) + this.eq_array.length + // INTEGER eq
				1 + this.countLength(this.c_array.length) + this.c_array.length; // INTEGER c

		final int total = 1 + this.countLength(content) + content; // SEQUENCE

		final byte[] plain = new byte[total];
		int index = 0;
		index = this.writeSEQUENCE(plain, index, content);
		index = this.writeINTEGER(plain, index, new byte[1]); // 0
		index = this.writeINTEGER(plain, index, this.n_array);
		index = this.writeINTEGER(plain, index, this.pub_array);
		index = this.writeINTEGER(plain, index, this.prv_array);
		index = this.writeINTEGER(plain, index, this.p_array);
		index = this.writeINTEGER(plain, index, this.q_array);
		index = this.writeINTEGER(plain, index, this.ep_array);
		index = this.writeINTEGER(plain, index, this.eq_array);
		index = this.writeINTEGER(plain, index, this.c_array);
		return plain;
	}

	@Override
	boolean parse(final byte[] plain) {

		try {
			int index = 0;
			int length = 0;

			if (this.vendor == VENDOR_PUTTY) {
				final Buffer buf = new Buffer(plain);
				buf.skip(plain.length);

				try {
					final byte[][] tmp = buf.getBytes(4, "");
					this.prv_array = tmp[0];
					this.p_array = tmp[1];
					this.q_array = tmp[2];
					this.c_array = tmp[3];
				} catch (final JSchException e) {
					return false;
				}

				this.getEPArray();
				this.getEQArray();

				return true;
			}

			if (this.vendor == VENDOR_FSECURE) {
				if (plain[index] != 0x30) { // FSecure
					final Buffer buf = new Buffer(plain);
					this.pub_array = buf.getMPIntBits();
					this.prv_array = buf.getMPIntBits();
					this.n_array = buf.getMPIntBits();
					buf.getMPIntBits();
					this.p_array = buf.getMPIntBits();
					this.q_array = buf.getMPIntBits();
					if (this.n_array != null) {
						this.key_size = (new java.math.BigInteger(this.n_array)).bitLength();
					}

					this.getEPArray();
					this.getEQArray();
					this.getCArray();

					return true;
				}
				return false;
			}

			/*
			 * Key must be in the following ASN.1 DER encoding,
			 * RSAPrivateKey ::= SEQUENCE {
			 * version Version,
			 * modulus INTEGER, -- n
			 * publicExponent INTEGER, -- e
			 * privateExponent INTEGER, -- d
			 * prime1 INTEGER, -- p
			 * prime2 INTEGER, -- q
			 * exponent1 INTEGER, -- d mod (p-1)
			 * exponent2 INTEGER, -- d mod (q-1)
			 * coefficient INTEGER, -- (inverse of q) mod p
			 * otherPrimeInfos OtherPrimeInfos OPTIONAL
			 * }
			 */

			index++; // SEQUENCE
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}

			if (plain[index] != 0x02) {
				return false;
			}
			index++; // INTEGER
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.n_array = new byte[length];
			System.arraycopy(plain, index, this.n_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.pub_array = new byte[length];
			System.arraycopy(plain, index, this.pub_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.prv_array = new byte[length];
			System.arraycopy(plain, index, this.prv_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.p_array = new byte[length];
			System.arraycopy(plain, index, this.p_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.q_array = new byte[length];
			System.arraycopy(plain, index, this.q_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.ep_array = new byte[length];
			System.arraycopy(plain, index, this.ep_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.eq_array = new byte[length];
			System.arraycopy(plain, index, this.eq_array, 0, length);
			index += length;

			index++;
			length = plain[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (plain[index++] & 0xff);
				}
			}
			this.c_array = new byte[length];
			System.arraycopy(plain, index, this.c_array, 0, length);
			index += length;

			if (this.n_array != null) {
				this.key_size = (new java.math.BigInteger(this.n_array)).bitLength();
			}

		} catch (final Exception e) {
			// System.err.println(e);
			return false;
		}
		return true;
	}

	@Override
	public byte[] getPublicKeyBlob() {
		final byte[] foo = super.getPublicKeyBlob();
		if (foo != null) {
			return foo;
		}

		if (this.pub_array == null) {
			return null;
		}
		final byte[][] tmp = new byte[3][];
		tmp[0] = sshrsa;
		tmp[1] = this.pub_array;
		tmp[2] = this.n_array;
		return Buffer.fromBytes(tmp).buffer;
	}

	private static final byte[] sshrsa = Util.str2byte("ssh-rsa");

	@Override
	byte[] getKeyTypeName() {
		return sshrsa;
	}

	@Override
	public int getKeyType() {
		return RSA;
	}

	@Override
	public int getKeySize() {
		return this.key_size;
	}

	@Override
	public byte[] getSignature(final byte[] data) {
		try {
			final Class<?> c = Class.forName(JSch.getConfig("signature.rsa"));
			final SignatureRSA rsa = (SignatureRSA) (c.newInstance());
			rsa.init();
			rsa.setPrvKey(this.prv_array, this.n_array);

			rsa.update(data);
			final byte[] sig = rsa.sign();
			final byte[][] tmp = new byte[2][];
			tmp[0] = sshrsa;
			tmp[1] = sig;
			return Buffer.fromBytes(tmp).buffer;
		} catch (final Exception e) {}
		return null;
	}

	@Override
	public Signature getVerifier() {
		try {
			final Class<?> c = Class.forName(JSch.getConfig("signature.rsa"));
			final SignatureRSA rsa = (SignatureRSA) (c.newInstance());
			rsa.init();

			if (this.pub_array == null && this.n_array == null && this.getPublicKeyBlob() != null) {
				final Buffer buf = new Buffer(this.getPublicKeyBlob());
				buf.getString();
				this.pub_array = buf.getString();
				this.n_array = buf.getString();
			}

			rsa.setPubKey(this.pub_array, this.n_array);
			return rsa;
		} catch (final Exception e) {}
		return null;
	}

	static KeyPair fromSSHAgent(final JSch jsch, final Buffer buf) throws JSchException {

		final byte[][] tmp = buf.getBytes(8, "invalid key format");

		final byte[] n_array = tmp[1];
		final byte[] pub_array = tmp[2];
		final byte[] prv_array = tmp[3];
		final KeyPairRSA kpair = new KeyPairRSA(jsch, n_array, pub_array, prv_array);
		kpair.c_array = tmp[4]; // iqmp
		kpair.p_array = tmp[5];
		kpair.q_array = tmp[6];
		kpair.publicKeyComment = new String(tmp[7]);
		kpair.vendor = VENDOR_OPENSSH;
		return kpair;
	}

	@Override
	public byte[] forSSHAgent() throws JSchException {
		if (this.isEncrypted()) {
			throw new JSchException("key is encrypted.");
		}
		final Buffer buf = new Buffer();
		buf.putString(sshrsa);
		buf.putString(this.n_array);
		buf.putString(this.pub_array);
		buf.putString(this.prv_array);
		buf.putString(this.getCArray());
		buf.putString(this.p_array);
		buf.putString(this.q_array);
		buf.putString(Util.str2byte(this.publicKeyComment));
		final byte[] result = new byte[buf.getLength()];
		buf.getByte(result, 0, result.length);
		return result;
	}

	private byte[] getEPArray() {
		if (this.ep_array == null) {
			this.ep_array = (new BigInteger(this.prv_array)).mod(new BigInteger(this.p_array).subtract(BigInteger.ONE)).toByteArray();
		}
		return this.ep_array;
	}

	private byte[] getEQArray() {
		if (this.eq_array == null) {
			this.eq_array = (new BigInteger(this.prv_array)).mod(new BigInteger(this.q_array).subtract(BigInteger.ONE)).toByteArray();
		}
		return this.eq_array;
	}

	private byte[] getCArray() {
		if (this.c_array == null) {
			this.c_array = (new BigInteger(this.q_array)).modInverse(new BigInteger(this.p_array)).toByteArray();
		}
		return this.c_array;
	}

	@Override
	public void dispose() {
		super.dispose();
		Util.bzero(this.prv_array);
	}
}
