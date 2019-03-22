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

public class KeyPairDSA extends KeyPair {

	private byte[] P_array;
	private byte[] Q_array;
	private byte[] G_array;
	private byte[] pub_array;
	private byte[] prv_array;

	// private int key_size=0;
	private int key_size = 1024;

	public KeyPairDSA(final JSch jsch) {
		this(jsch, null, null, null, null, null);
	}

	public KeyPairDSA(final JSch jsch,
			final byte[] P_array,
			final byte[] Q_array,
			final byte[] G_array,
			final byte[] pub_array,
			final byte[] prv_array) {
		super(jsch);
		this.P_array = P_array;
		this.Q_array = Q_array;
		this.G_array = G_array;
		this.pub_array = pub_array;
		this.prv_array = prv_array;
		if (P_array != null) {
			this.key_size = new java.math.BigInteger(P_array).bitLength();
		}
	}

	@Override
	void generate(final int key_size) throws JSchException {
		this.key_size = key_size;
		try {
			final Class<?> c = Class.forName(JSch.getConfig("keypairgen.dsa"));
			KeyPairGenDSA keypairgen = (KeyPairGenDSA) c.newInstance();
			keypairgen.init(key_size);
			this.P_array = keypairgen.getP();
			this.Q_array = keypairgen.getQ();
			this.G_array = keypairgen.getG();
			this.pub_array = keypairgen.getY();
			this.prv_array = keypairgen.getX();

			keypairgen = null;
		} catch (final Exception e) {
			// System.err.println("KeyPairDSA: "+e);
			throw new JSchException(e.toString(), e);
		}
	}

	private static final byte[] begin = Util.str2byte("-----BEGIN DSA PRIVATE KEY-----");
	private static final byte[] end = Util.str2byte("-----END DSA PRIVATE KEY-----");

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
				1 + this.countLength(this.P_array.length) + this.P_array.length + // INTEGER P
				1 + this.countLength(this.Q_array.length) + this.Q_array.length + // INTEGER Q
				1 + this.countLength(this.G_array.length) + this.G_array.length + // INTEGER G
				1 + this.countLength(this.pub_array.length) + this.pub_array.length + // INTEGER pub
				1 + this.countLength(this.prv_array.length) + this.prv_array.length; // INTEGER prv

		final int total = 1 + this.countLength(content) + content; // SEQUENCE

		final byte[] plain = new byte[total];
		int index = 0;
		index = this.writeSEQUENCE(plain, index, content);
		index = this.writeINTEGER(plain, index, new byte[1]); // 0
		index = this.writeINTEGER(plain, index, this.P_array);
		index = this.writeINTEGER(plain, index, this.Q_array);
		index = this.writeINTEGER(plain, index, this.G_array);
		index = this.writeINTEGER(plain, index, this.pub_array);
		index = this.writeINTEGER(plain, index, this.prv_array);
		return plain;
	}

	@Override
	boolean parse(final byte[] plain) {
		try {

			if (this.vendor == VENDOR_FSECURE) {
				if (plain[0] != 0x30) { // FSecure
					final Buffer buf = new Buffer(plain);
					buf.getInt();
					this.P_array = buf.getMPIntBits();
					this.G_array = buf.getMPIntBits();
					this.Q_array = buf.getMPIntBits();
					this.pub_array = buf.getMPIntBits();
					this.prv_array = buf.getMPIntBits();
					if (this.P_array != null) {
						this.key_size = new java.math.BigInteger(this.P_array).bitLength();
					}
					return true;
				}
				return false;
			} else if (this.vendor == VENDOR_PUTTY) {
				final Buffer buf = new Buffer(plain);
				buf.skip(plain.length);

				try {
					final byte[][] tmp = buf.getBytes(1, "");
					this.prv_array = tmp[0];
				} catch (final JSchException e) {
					return false;
				}

				return true;
			}

			int index = 0;
			int length = 0;

			if (plain[index] != 0x30) {
				return false;
			}
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
			this.P_array = new byte[length];
			System.arraycopy(plain, index, this.P_array, 0, length);
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
			this.Q_array = new byte[length];
			System.arraycopy(plain, index, this.Q_array, 0, length);
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
			this.G_array = new byte[length];
			System.arraycopy(plain, index, this.G_array, 0, length);
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

			if (this.P_array != null) {
				this.key_size = new java.math.BigInteger(this.P_array).bitLength();
			}
		} catch (final Exception e) {
			// System.err.println(e);
			// e.printStackTrace();
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

		if (this.P_array == null) {
			return null;
		}
		final byte[][] tmp = new byte[5][];
		tmp[0] = sshdss;
		tmp[1] = this.P_array;
		tmp[2] = this.Q_array;
		tmp[3] = this.G_array;
		tmp[4] = this.pub_array;
		return Buffer.fromBytes(tmp).buffer;
	}

	private static final byte[] sshdss = Util.str2byte("ssh-dss");

	@Override
	byte[] getKeyTypeName() {
		return sshdss;
	}

	@Override
	public int getKeyType() {
		return DSA;
	}

	@Override
	public int getKeySize() {
		return this.key_size;
	}

	@Override
	public byte[] getSignature(final byte[] data) {
		try {
			final Class<?> c = Class.forName(JSch.getConfig("signature.dss"));
			final SignatureDSA dsa = (SignatureDSA) c.newInstance();
			dsa.init();
			dsa.setPrvKey(this.prv_array, this.P_array, this.Q_array, this.G_array);

			dsa.update(data);
			final byte[] sig = dsa.sign();
			final byte[][] tmp = new byte[2][];
			tmp[0] = sshdss;
			tmp[1] = sig;
			return Buffer.fromBytes(tmp).buffer;
		} catch (final Exception e) {
			// System.err.println("e "+e);
		}
		return null;
	}

	@Override
	public Signature getVerifier() {
		try {
			final Class<?> c = Class.forName(JSch.getConfig("signature.dss"));
			final SignatureDSA dsa = (SignatureDSA) c.newInstance();
			dsa.init();

			if (this.pub_array == null && this.P_array == null && this.getPublicKeyBlob() != null) {
				final Buffer buf = new Buffer(this.getPublicKeyBlob());
				buf.getString();
				this.P_array = buf.getString();
				this.Q_array = buf.getString();
				this.G_array = buf.getString();
				this.pub_array = buf.getString();
			}

			dsa.setPubKey(this.pub_array, this.P_array, this.Q_array, this.G_array);
			return dsa;
		} catch (final Exception e) {
			// System.err.println("e "+e);
		}
		return null;
	}

	static KeyPair fromSSHAgent(final JSch jsch, final Buffer buf) throws JSchException {

		final byte[][] tmp = buf.getBytes(7, "invalid key format");

		final byte[] P_array = tmp[1];
		final byte[] Q_array = tmp[2];
		final byte[] G_array = tmp[3];
		final byte[] pub_array = tmp[4];
		final byte[] prv_array = tmp[5];
		final KeyPairDSA kpair = new KeyPairDSA(jsch,
				P_array, Q_array, G_array,
				pub_array, prv_array);
		kpair.publicKeyComment = new String(tmp[6]);
		kpair.vendor = VENDOR_OPENSSH;
		return kpair;
	}

	@Override
	public byte[] forSSHAgent() throws JSchException {
		if (this.isEncrypted()) {
			throw new JSchException("key is encrypted.");
		}
		final Buffer buf = new Buffer();
		buf.putString(sshdss);
		buf.putString(this.P_array);
		buf.putString(this.Q_array);
		buf.putString(this.G_array);
		buf.putString(this.pub_array);
		buf.putString(this.prv_array);
		buf.putString(Util.str2byte(this.publicKeyComment));
		final byte[] result = new byte[buf.getLength()];
		buf.getByte(result, 0, result.length);
		return result;
	}

	@Override
	public void dispose() {
		super.dispose();
		Util.bzero(this.prv_array);
	}
}
