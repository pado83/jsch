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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public abstract class KeyPair {

	public static final int ERROR = 0;
	public static final int DSA = 1;
	public static final int RSA = 2;
	public static final int ECDSA = 3;
	public static final int UNKNOWN = 4;

	static final int VENDOR_OPENSSH = 0;
	static final int VENDOR_FSECURE = 1;
	static final int VENDOR_PUTTY = 2;
	static final int VENDOR_PKCS8 = 3;

	int vendor = VENDOR_OPENSSH;

	private static final byte[] cr = Util.str2byte("\n");

	public static KeyPair genKeyPair(final JSch jsch, final int type) throws JSchException {
		return genKeyPair(jsch, type, 1024);
	}

	public static KeyPair genKeyPair(final JSch jsch, final int type, final int key_size) throws JSchException {
		KeyPair kpair = null;
		if (type == DSA) {
			kpair = new KeyPairDSA(jsch);
		} else if (type == RSA) {
			kpair = new KeyPairRSA(jsch);
		} else if (type == ECDSA) {
			kpair = new KeyPairECDSA(jsch);
		}
		if (kpair != null) {
			kpair.generate(key_size);
		}
		return kpair;
	}

	abstract void generate(int key_size) throws JSchException;

	abstract byte[] getBegin();

	abstract byte[] getEnd();

	abstract int getKeySize();

	public abstract byte[] getSignature(byte[] data);

	public abstract Signature getVerifier();

	public abstract byte[] forSSHAgent() throws JSchException;

	public String getPublicKeyComment() {
		return this.publicKeyComment;
	}

	public void setPublicKeyComment(final String publicKeyComment) {
		this.publicKeyComment = publicKeyComment;
	}

	protected String publicKeyComment = "no comment";

	JSch jsch = null;
	private Cipher cipher;
	private HASH hash;
	private Random random;

	private byte[] passphrase;

	public KeyPair(final JSch jsch) {
		this.jsch = jsch;
	}

	static byte[][] header = { Util.str2byte("Proc-Type: 4,ENCRYPTED"),
			Util.str2byte("DEK-Info: DES-EDE3-CBC,") };

	abstract byte[] getPrivateKey();

	/**
	 * Writes the plain private key to the given output stream.
	 *
	 * @param out output stream
	 * @see #writePrivateKey(java.io.OutputStream out, byte[] passphrase)
	 */
	public void writePrivateKey(final java.io.OutputStream out) {
		this.writePrivateKey(out, null);
	}

	/**
	 * Writes the cyphered private key to the given output stream.
	 *
	 * @param out output stream
	 * @param passphrase a passphrase to encrypt the private key
	 */
	public void writePrivateKey(final java.io.OutputStream out, byte[] passphrase) {
		if (passphrase == null) {
			passphrase = this.passphrase;
		}

		final byte[] plain = this.getPrivateKey();
		final byte[][] _iv = new byte[1][];
		final byte[] encoded = this.encrypt(plain, _iv, passphrase);
		if (encoded != plain) {
			Util.bzero(plain);
		}
		final byte[] iv = _iv[0];
		final byte[] prv = Util.toBase64(encoded, 0, encoded.length);

		try {
			out.write(this.getBegin());
			out.write(cr);
			if (passphrase != null) {
				out.write(header[0]);
				out.write(cr);
				out.write(header[1]);
				for (final byte element : iv) {
					out.write(b2a((byte) (element >>> 4 & 0x0f)));
					out.write(b2a((byte) (element & 0x0f)));
				}
				out.write(cr);
				out.write(cr);
			}
			int i = 0;
			while (i < prv.length) {
				if (i + 64 < prv.length) {
					out.write(prv, i, 64);
					out.write(cr);
					i += 64;
					continue;
				}
				out.write(prv, i, prv.length - i);
				out.write(cr);
				break;
			}
			out.write(this.getEnd());
			out.write(cr);
			// out.close();
		} catch (final Exception e) {}
	}

	private static byte[] space = Util.str2byte(" ");

	abstract byte[] getKeyTypeName();

	public abstract int getKeyType();

	/**
	 * Returns the blob of the public key.
	 *
	 * @return blob of the public key
	 */
	public byte[] getPublicKeyBlob() {
		// TODO JSchException should be thrown
		// if(publickeyblob == null)
		// throw new JSchException("public-key blob is not available");
		return this.publickeyblob;
	}

	/**
	 * Writes the public key with the specified comment to the output stream.
	 *
	 * @param out output stream
	 * @param comment comment
	 */
	public void writePublicKey(final java.io.OutputStream out, final String comment) {
		final byte[] pubblob = this.getPublicKeyBlob();
		final byte[] pub = Util.toBase64(pubblob, 0, pubblob.length);
		try {
			out.write(this.getKeyTypeName());
			out.write(space);
			out.write(pub, 0, pub.length);
			out.write(space);
			out.write(Util.str2byte(comment));
			out.write(cr);
		} catch (final Exception e) {}
	}

	/**
	 * Writes the public key with the specified comment to the file.
	 *
	 * @param name file name
	 * @param comment comment
	 * @see #writePublicKey(java.io.OutputStream out, String comment)
	 */
	public void writePublicKey(final String name, final String comment) throws java.io.FileNotFoundException, java.io.IOException {
		final FileOutputStream fos = new FileOutputStream(name);
		this.writePublicKey(fos, comment);
		fos.close();
	}

	/**
	 * Writes the public key with the specified comment to the output stream in
	 * the format defined in http://www.ietf.org/rfc/rfc4716.txt
	 *
	 * @param out output stream
	 * @param comment comment
	 */
	public void writeSECSHPublicKey(final java.io.OutputStream out, final String comment) {
		final byte[] pubblob = this.getPublicKeyBlob();
		final byte[] pub = Util.toBase64(pubblob, 0, pubblob.length);
		try {
			out.write(Util.str2byte("---- BEGIN SSH2 PUBLIC KEY ----"));
			out.write(cr);
			out.write(Util.str2byte("Comment: \"" + comment + "\""));
			out.write(cr);
			int index = 0;
			while (index < pub.length) {
				int len = 70;
				if (pub.length - index < len) {
					len = pub.length - index;
				}
				out.write(pub, index, len);
				out.write(cr);
				index += len;
			}
			out.write(Util.str2byte("---- END SSH2 PUBLIC KEY ----"));
			out.write(cr);
		} catch (final Exception e) {}
	}

	/**
	 * Writes the public key with the specified comment to the output stream in
	 * the format defined in http://www.ietf.org/rfc/rfc4716.txt
	 *
	 * @param name file name
	 * @param comment comment
	 * @see #writeSECSHPublicKey(java.io.OutputStream out, String comment)
	 */
	public void writeSECSHPublicKey(final String name, final String comment) throws java.io.FileNotFoundException, java.io.IOException {
		final FileOutputStream fos = new FileOutputStream(name);
		this.writeSECSHPublicKey(fos, comment);
		fos.close();
	}

	/**
	 * Writes the plain private key to the file.
	 *
	 * @param name file name
	 * @see #writePrivateKey(String name, byte[] passphrase)
	 */
	public void writePrivateKey(final String name) throws java.io.FileNotFoundException, java.io.IOException {
		this.writePrivateKey(name, null);
	}

	/**
	 * Writes the cyphered private key to the file.
	 *
	 * @param name file name
	 * @param passphrase a passphrase to encrypt the private key
	 * @see #writePrivateKey(java.io.OutputStream out, byte[] passphrase)
	 */
	public void writePrivateKey(final String name, final byte[] passphrase) throws java.io.FileNotFoundException, java.io.IOException {
		final FileOutputStream fos = new FileOutputStream(name);
		this.writePrivateKey(fos, passphrase);
		fos.close();
	}

	/**
	 * Returns the finger-print of the public key.
	 *
	 * @return finger print
	 */
	public String getFingerPrint() {
		if (this.hash == null) {
			this.hash = this.genHash();
		}
		final byte[] kblob = this.getPublicKeyBlob();
		if (kblob == null) {
			return null;
		}
		return Util.getFingerPrint(this.hash, kblob);
	}

	private byte[] encrypt(final byte[] plain, final byte[][] _iv, final byte[] passphrase) {
		if (passphrase == null) {
			return plain;
		}

		if (this.cipher == null) {
			this.cipher = this.genCipher();
		}
		final byte[] iv = _iv[0] = new byte[this.cipher.getIVSize()];

		if (this.random == null) {
			this.random = this.genRandom();
		}
		this.random.fill(iv, 0, iv.length);

		final byte[] key = this.genKey(passphrase, iv);
		byte[] encoded = plain;

		// PKCS#5Padding
		{
			// int bsize=cipher.getBlockSize();
			final int bsize = this.cipher.getIVSize();
			final byte[] foo = new byte[(encoded.length / bsize + 1) * bsize];
			System.arraycopy(encoded, 0, foo, 0, encoded.length);
			final int padding = bsize - encoded.length % bsize;
			for (int i = foo.length - 1; foo.length - padding <= i; i--) {
				foo[i] = (byte) padding;
			}
			encoded = foo;
		}

		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			this.cipher.update(encoded, 0, encoded.length, encoded, 0);
		} catch (final Exception e) {
			// System.err.println(e);
		}
		Util.bzero(key);
		return encoded;
	}

	abstract boolean parse(byte[] data);

	private byte[] decrypt(final byte[] data, final byte[] passphrase, final byte[] iv) {

		try {
			final byte[] key = this.genKey(passphrase, iv);
			this.cipher.init(Cipher.DECRYPT_MODE, key, iv);
			Util.bzero(key);
			final byte[] plain = new byte[data.length];
			this.cipher.update(data, 0, data.length, plain, 0);
			return plain;
		} catch (final Exception e) {
			// System.err.println(e);
		}
		return null;
	}

	int writeSEQUENCE(final byte[] buf, int index, final int len) {
		buf[index++] = 0x30;
		index = this.writeLength(buf, index, len);
		return index;
	}

	int writeINTEGER(final byte[] buf, int index, final byte[] data) {
		buf[index++] = 0x02;
		index = this.writeLength(buf, index, data.length);
		System.arraycopy(data, 0, buf, index, data.length);
		index += data.length;
		return index;
	}

	int writeOCTETSTRING(final byte[] buf, int index, final byte[] data) {
		buf[index++] = 0x04;
		index = this.writeLength(buf, index, data.length);
		System.arraycopy(data, 0, buf, index, data.length);
		index += data.length;
		return index;
	}

	int writeDATA(final byte[] buf, final byte n, int index, final byte[] data) {
		buf[index++] = n;
		index = this.writeLength(buf, index, data.length);
		System.arraycopy(data, 0, buf, index, data.length);
		index += data.length;
		return index;
	}

	int countLength(int len) {
		int i = 1;
		if (len <= 0x7f) {
			return i;
		}
		while (len > 0) {
			len >>>= 8;
			i++;
		}
		return i;
	}

	int writeLength(final byte[] data, int index, int len) {
		int i = this.countLength(len) - 1;
		if (i == 0) {
			data[index++] = (byte) len;
			return index;
		}
		data[index++] = (byte) (0x80 | i);
		final int j = index + i;
		while (i > 0) {
			data[index + i - 1] = (byte) (len & 0xff);
			len >>>= 8;
			i--;
		}
		return j;
	}

	private Random genRandom() {
		if (this.random == null) {
			try {
				final Class<?> c = Class.forName(JSch.getConfig("random"));
				this.random = (Random) c.newInstance();
			} catch (final Exception e) {
				System.err.println("connect: random " + e);
			}
		}
		return this.random;
	}

	private HASH genHash() {
		try {
			final Class<?> c = Class.forName(JSch.getConfig("md5"));
			this.hash = (HASH) c.newInstance();
			this.hash.init();
		} catch (final Exception e) {}
		return this.hash;
	}

	private Cipher genCipher() {
		try {
			Class<?> c;
			c = Class.forName(JSch.getConfig("3des-cbc"));
			this.cipher = (Cipher) c.newInstance();
		} catch (final Exception e) {}
		return this.cipher;
	}

	/*
	 * hash is MD5
	 * h(0) <- hash(passphrase, iv);
	 * h(n) <- hash(h(n-1), passphrase, iv);
	 * key <- (h(0),...,h(n))[0,..,key.length];
	 */
	synchronized byte[] genKey(final byte[] passphrase, final byte[] iv) {
		if (this.cipher == null) {
			this.cipher = this.genCipher();
		}
		if (this.hash == null) {
			this.hash = this.genHash();
		}

		byte[] key = new byte[this.cipher.getBlockSize()];
		final int hsize = this.hash.getBlockSize();
		final byte[] hn = new byte[key.length / hsize * hsize +
				(key.length % hsize == 0 ? 0 : hsize)];
		try {
			byte[] tmp = null;
			if (this.vendor == VENDOR_OPENSSH) {
				for (int index = 0; index + hsize <= hn.length;) {
					if (tmp != null) {
						this.hash.update(tmp, 0, tmp.length);
					}
					this.hash.update(passphrase, 0, passphrase.length);
					this.hash.update(iv, 0, iv.length > 8 ? 8 : iv.length);
					tmp = this.hash.digest();
					System.arraycopy(tmp, 0, hn, index, tmp.length);
					index += tmp.length;
				}
				System.arraycopy(hn, 0, key, 0, key.length);
			} else if (this.vendor == VENDOR_FSECURE) {
				for (int index = 0; index + hsize <= hn.length;) {
					if (tmp != null) {
						this.hash.update(tmp, 0, tmp.length);
					}
					this.hash.update(passphrase, 0, passphrase.length);
					tmp = this.hash.digest();
					System.arraycopy(tmp, 0, hn, index, tmp.length);
					index += tmp.length;
				}
				System.arraycopy(hn, 0, key, 0, key.length);
			} else if (this.vendor == VENDOR_PUTTY) {
				final Class<?> c = Class.forName(JSch.getConfig("sha-1"));
				final HASH sha1 = (HASH) c.newInstance();
				tmp = new byte[4];
				key = new byte[20 * 2];
				for (int i = 0; i < 2; i++) {
					sha1.init();
					tmp[3] = (byte) i;
					sha1.update(tmp, 0, tmp.length);
					sha1.update(passphrase, 0, passphrase.length);
					System.arraycopy(sha1.digest(), 0, key, i * 20, 20);
				}
			}
		} catch (final Exception e) {
			System.err.println(e);
		}
		return key;
	}

	/**
	 * @deprecated use #writePrivateKey(java.io.OutputStream out, byte[] passphrase)
	 */
	@Deprecated
	public void setPassphrase(final String passphrase) {
		if (passphrase == null || passphrase.length() == 0) {
			this.setPassphrase((byte[]) null);
		} else {
			this.setPassphrase(Util.str2byte(passphrase));
		}
	}

	/**
	 * @deprecated use #writePrivateKey(String name, byte[] passphrase)
	 */
	@Deprecated
	public void setPassphrase(byte[] passphrase) {
		if (passphrase != null && passphrase.length == 0) {
			passphrase = null;
		}
		this.passphrase = passphrase;
	}

	protected boolean encrypted = false;
	protected byte[] data = null;
	private byte[] iv = null;
	private byte[] publickeyblob = null;

	public boolean isEncrypted() {
		return this.encrypted;
	}

	public boolean decrypt(final String _passphrase) {
		if (_passphrase == null || _passphrase.length() == 0) {
			return !this.encrypted;
		}
		return this.decrypt(Util.str2byte(_passphrase));
	}

	public boolean decrypt(byte[] _passphrase) {

		if (!this.encrypted) {
			return true;
		}
		if (_passphrase == null) {
			return !this.encrypted;
		}
		final byte[] bar = new byte[_passphrase.length];
		System.arraycopy(_passphrase, 0, bar, 0, bar.length);
		_passphrase = bar;
		final byte[] foo = this.decrypt(this.data, _passphrase, this.iv);
		Util.bzero(_passphrase);
		if (this.parse(foo)) {
			this.encrypted = false;
		}
		return !this.encrypted;
	}

	public static KeyPair load(final JSch jsch, final String prvkey) throws JSchException {
		String pubkey = prvkey + ".pub";
		if (!new File(pubkey).exists()) {
			pubkey = null;
		}
		return load(jsch, prvkey, pubkey);
	}

	public static KeyPair load(final JSch jsch, final String prvfile, final String pubfile) throws JSchException {

		byte[] prvkey = null;
		byte[] pubkey = null;

		try {
			prvkey = Util.fromFile(prvfile);
		} catch (final IOException e) {
			throw new JSchException(e.toString(), e);
		}

		String _pubfile = pubfile;
		if (pubfile == null) {
			_pubfile = prvfile + ".pub";
		}

		try {
			pubkey = Util.fromFile(_pubfile);
		} catch (final IOException e) {
			if (pubfile != null) {
				throw new JSchException(e.toString(), e);
			}
		}

		try {
			return load(jsch, prvkey, pubkey);
		} finally {
			Util.bzero(prvkey);
		}
	}

	public static KeyPair load(final JSch jsch, final byte[] prvkey, final byte[] pubkey) throws JSchException {

		byte[] iv = new byte[8]; // 8
		boolean encrypted = true;
		byte[] data = null;

		byte[] publickeyblob = null;

		int type = ERROR;
		int vendor = VENDOR_OPENSSH;
		String publicKeyComment = "";
		Cipher cipher = null;

		// prvkey from "ssh-add" command on the remote.
		if (pubkey == null &&
				prvkey != null &&
				prvkey.length > 11 &&
				prvkey[0] == 0 && prvkey[1] == 0 && prvkey[2] == 0 &&
				(prvkey[3] == 7 || prvkey[3] == 19)) {

			final Buffer buf = new Buffer(prvkey);
			buf.skip(prvkey.length); // for using Buffer#available()
			final String _type = new String(buf.getString()); // ssh-rsa or ssh-dss
			buf.rewind();

			KeyPair kpair = null;
			if (_type.equals("ssh-rsa")) {
				kpair = KeyPairRSA.fromSSHAgent(jsch, buf);
			} else if (_type.equals("ssh-dss")) {
				kpair = KeyPairDSA.fromSSHAgent(jsch, buf);
			} else if (_type.equals("ecdsa-sha2-nistp256") ||
					_type.equals("ecdsa-sha2-nistp384") ||
					_type.equals("ecdsa-sha2-nistp521")) {
				kpair = KeyPairECDSA.fromSSHAgent(jsch, buf);
			} else {
				throw new JSchException("privatekey: invalid key " + new String(prvkey, 4, 7));
			}
			return kpair;
		}

		try {
			byte[] buf = prvkey;

			if (buf != null) {
				final KeyPair ppk = loadPPK(jsch, buf);
				if (ppk != null) {
					return ppk;
				}
			}

			int len = buf != null ? buf.length : 0;
			int i = 0;

			// skip garbage lines.
			while (i < len) {
				if (buf[i] == '-' && i + 4 < len &&
						buf[i + 1] == '-' && buf[i + 2] == '-' &&
						buf[i + 3] == '-' && buf[i + 4] == '-') {
					break;
				}
				i++;
			}

			while (i < len) {
				if (buf[i] == 'B' && i + 3 < len && buf[i + 1] == 'E' && buf[i + 2] == 'G' && buf[i + 3] == 'I') {
					i += 6;
					if (i + 2 >= len) {
						throw new JSchException("invalid privatekey: " + prvkey);
					}
					if (buf[i] == 'D' && buf[i + 1] == 'S' && buf[i + 2] == 'A') {
						type = DSA;
					} else if (buf[i] == 'R' && buf[i + 1] == 'S' && buf[i + 2] == 'A') {
						type = RSA;
					} else if (buf[i] == 'E' && buf[i + 1] == 'C') {
						type = ECDSA;
					} else if (buf[i] == 'S' && buf[i + 1] == 'S' && buf[i + 2] == 'H') { // FSecure
						type = UNKNOWN;
						vendor = VENDOR_FSECURE;
					} else if (i + 6 < len &&
							buf[i] == 'P' && buf[i + 1] == 'R' &&
							buf[i + 2] == 'I' && buf[i + 3] == 'V' &&
							buf[i + 4] == 'A' && buf[i + 5] == 'T' && buf[i + 6] == 'E') {
						type = UNKNOWN;
						vendor = VENDOR_PKCS8;
						encrypted = false;
						i += 3;
					} else if (i + 8 < len &&
							buf[i] == 'E' && buf[i + 1] == 'N' &&
							buf[i + 2] == 'C' && buf[i + 3] == 'R' &&
							buf[i + 4] == 'Y' && buf[i + 5] == 'P' && buf[i + 6] == 'T' &&
							buf[i + 7] == 'E' && buf[i + 8] == 'D') {
						type = UNKNOWN;
						vendor = VENDOR_PKCS8;
						i += 5;
					} else {
						throw new JSchException("invalid privatekey: " + prvkey);
					}
					i += 3;
					continue;
				}
				if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-' &&
						buf[i + 4] == '2' && buf[i + 5] == '5' && buf[i + 6] == '6' && buf[i + 7] == '-') {
					i += 8;
					if (Session.checkCipher(JSch.getConfig("aes256-cbc"))) {
						final Class<?> c = Class.forName(JSch.getConfig("aes256-cbc"));
						cipher = (Cipher) c.newInstance();
						// key=new byte[cipher.getBlockSize()];
						iv = new byte[cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes256-cbc is not available " + prvkey);
					}
					continue;
				}
				if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-' &&
						buf[i + 4] == '1' && buf[i + 5] == '9' && buf[i + 6] == '2' && buf[i + 7] == '-') {
					i += 8;
					if (Session.checkCipher(JSch.getConfig("aes192-cbc"))) {
						final Class<?> c = Class.forName(JSch.getConfig("aes192-cbc"));
						cipher = (Cipher) c.newInstance();
						// key=new byte[cipher.getBlockSize()];
						iv = new byte[cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes192-cbc is not available " + prvkey);
					}
					continue;
				}
				if (buf[i] == 'A' && i + 7 < len && buf[i + 1] == 'E' && buf[i + 2] == 'S' && buf[i + 3] == '-' &&
						buf[i + 4] == '1' && buf[i + 5] == '2' && buf[i + 6] == '8' && buf[i + 7] == '-') {
					i += 8;
					if (Session.checkCipher(JSch.getConfig("aes128-cbc"))) {
						final Class<?> c = Class.forName(JSch.getConfig("aes128-cbc"));
						cipher = (Cipher) c.newInstance();
						// key=new byte[cipher.getBlockSize()];
						iv = new byte[cipher.getIVSize()];
					} else {
						throw new JSchException("privatekey: aes128-cbc is not available " + prvkey);
					}
					continue;
				}
				if (buf[i] == 'C' && i + 3 < len && buf[i + 1] == 'B' && buf[i + 2] == 'C' && buf[i + 3] == ',') {
					i += 4;
					for (int ii = 0; ii < iv.length; ii++) {
						iv[ii] = (byte) ((a2b(buf[i++]) << 4 & 0xf0) + (a2b(buf[i++]) & 0xf));
					}
					continue;
				}
				if (buf[i] == 0x0d && i + 1 < buf.length && buf[i + 1] == 0x0a) {
					i++;
					continue;
				}
				if (buf[i] == 0x0a && i + 1 < buf.length) {
					if (buf[i + 1] == 0x0a) {
						i += 2;
						break;
					}
					if (buf[i + 1] == 0x0d &&
							i + 2 < buf.length && buf[i + 2] == 0x0a) {
						i += 3;
						break;
					}
					boolean inheader = false;
					for (int j = i + 1; j < buf.length; j++) {
						if (buf[j] == 0x0a) {
							break;
						}
						// if(buf[j]==0x0d) break;
						if (buf[j] == ':') {
							inheader = true;
							break;
						}
					}
					if (!inheader) {
						i++;
						if (vendor != VENDOR_PKCS8) {
							encrypted = false; // no passphrase
						}
						break;
					}
				}
				i++;
			}

			if (buf != null) {

				if (type == ERROR) {
					throw new JSchException("invalid privatekey: " + prvkey);
				}

				int start = i;
				while (i < len) {
					if (buf[i] == '-') {
						break;
					}
					i++;
				}

				if (len - i == 0 || i - start == 0) {
					throw new JSchException("invalid privatekey: " + prvkey);
				}

				// The content of 'buf' will be changed, so it should be copied.
				final byte[] tmp = new byte[i - start];
				System.arraycopy(buf, start, tmp, 0, tmp.length);
				final byte[] _buf = tmp;

				start = 0;
				i = 0;

				int _len = _buf.length;
				while (i < _len) {
					if (_buf[i] == 0x0a) {
						final boolean xd = _buf[i - 1] == 0x0d;
						// ignore 0x0a (or 0x0d0x0a)
						System.arraycopy(_buf, i + 1, _buf, i - (xd ? 1 : 0), _len - (i + 1));
						if (xd) {
							_len--;
						}
						_len--;
						continue;
					}
					if (_buf[i] == '-') {
						break;
					}
					i++;
				}

				if (i - start > 0) {
					data = Util.fromBase64(_buf, start, i - start);
				}

				Util.bzero(_buf);
			}

			if (data != null &&
					data.length > 4 && // FSecure
					data[0] == (byte) 0x3f &&
					data[1] == (byte) 0x6f &&
					data[2] == (byte) 0xf9 &&
					data[3] == (byte) 0xeb) {

				final Buffer _buf = new Buffer(data);
				_buf.getInt(); // 0x3f6ff9be
				_buf.getInt();
				_buf.getString();
				// System.err.println("type: "+new String(_type));
				final String _cipher = Util.byte2str(_buf.getString());
				// System.err.println("cipher: "+_cipher);
				if (_cipher.equals("3des-cbc")) {
					_buf.getInt();
					final byte[] foo = new byte[data.length - _buf.getOffSet()];
					_buf.getByte(foo);
					data = foo;
					encrypted = true;
					throw new JSchException("unknown privatekey format: " + prvkey);
				} else if (_cipher.equals("none")) {
					_buf.getInt();
					_buf.getInt();

					encrypted = false;

					final byte[] foo = new byte[data.length - _buf.getOffSet()];
					_buf.getByte(foo);
					data = foo;
				}
			}

			if (pubkey != null) {
				try {
					buf = pubkey;
					len = buf.length;
					if (buf.length > 4 && // FSecure's public key
							buf[0] == '-' && buf[1] == '-' && buf[2] == '-' && buf[3] == '-') {

						boolean valid = true;
						i = 0;
						do {
							i++;
						} while (buf.length > i && buf[i] != 0x0a);
						if (buf.length <= i) {
							valid = false;
						}

						while (valid) {
							if (buf[i] == 0x0a) {
								boolean inheader = false;
								for (int j = i + 1; j < buf.length; j++) {
									if (buf[j] == 0x0a) {
										break;
									}
									if (buf[j] == ':') {
										inheader = true;
										break;
									}
								}
								if (!inheader) {
									i++;
									break;
								}
							}
							i++;
						}
						if (buf.length <= i) {
							valid = false;
						}

						final int start = i;
						while (valid && i < len) {
							if (buf[i] == 0x0a) {
								System.arraycopy(buf, i + 1, buf, i, len - i - 1);
								len--;
								continue;
							}
							if (buf[i] == '-') {
								break;
							}
							i++;
						}
						if (valid) {
							publickeyblob = Util.fromBase64(buf, start, i - start);
							if (prvkey == null || type == UNKNOWN) {
								if (publickeyblob[8] == 'd') {
									type = DSA;
								} else if (publickeyblob[8] == 'r') {
									type = RSA;
								}
							}
						}
					} else {
						if (buf[0] == 's' && buf[1] == 's' && buf[2] == 'h' && buf[3] == '-') {
							if (prvkey == null &&
									buf.length > 7) {
								if (buf[4] == 'd') {
									type = DSA;
								} else if (buf[4] == 'r') {
									type = RSA;
								}
							}
							i = 0;
							while (i < len) {
								if (buf[i] == ' ') {
									break;
								}
								i++;
							}
							i++;
							if (i < len) {
								final int start = i;
								while (i < len) {
									if (buf[i] == ' ') {
										break;
									}
									i++;
								}
								publickeyblob = Util.fromBase64(buf, start, i - start);
							}
							if (i++ < len) {
								final int start = i;
								while (i < len) {
									if (buf[i] == '\n') {
										break;
									}
									i++;
								}
								if (i > 0 && buf[i - 1] == 0x0d) {
									i--;
								}
								if (start < i) {
									publicKeyComment = new String(buf, start, i - start);
								}
							}
						} else if (buf[0] == 'e' && buf[1] == 'c' && buf[2] == 'd' && buf[3] == 's') {
							if (prvkey == null && buf.length > 7) {
								type = ECDSA;
							}
							i = 0;
							while (i < len) {
								if (buf[i] == ' ') {
									break;
								}
								i++;
							}
							i++;
							if (i < len) {
								final int start = i;
								while (i < len) {
									if (buf[i] == ' ') {
										break;
									}
									i++;
								}
								publickeyblob = Util.fromBase64(buf, start, i - start);
							}
							if (i++ < len) {
								final int start = i;
								while (i < len) {
									if (buf[i] == '\n') {
										break;
									}
									i++;
								}
								if (i > 0 && buf[i - 1] == 0x0d) {
									i--;
								}
								if (start < i) {
									publicKeyComment = new String(buf, start, i - start);
								}
							}
						}
					}
				} catch (final Exception ee) {}
			}
		} catch (final Exception e) {
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			throw new JSchException(e.toString(), e);
		}

		KeyPair kpair = null;
		if (type == DSA) {
			kpair = new KeyPairDSA(jsch);
		} else if (type == RSA) {
			kpair = new KeyPairRSA(jsch);
		} else if (type == ECDSA) {
			kpair = new KeyPairECDSA(jsch, pubkey);
		} else if (vendor == VENDOR_PKCS8) {
			kpair = new KeyPairPKCS8(jsch);
		}

		if (kpair != null) {
			kpair.encrypted = encrypted;
			kpair.publickeyblob = publickeyblob;
			kpair.vendor = vendor;
			kpair.publicKeyComment = publicKeyComment;
			kpair.cipher = cipher;

			if (encrypted) {
				kpair.encrypted = true;
				kpair.iv = iv;
				kpair.data = data;
			} else {
				if (kpair.parse(data)) {
					kpair.encrypted = false;
					return kpair;
				}
				throw new JSchException("invalid privatekey: " + prvkey);
			}
		}

		return kpair;
	}

	static private byte a2b(final byte c) {
		if ('0' <= c && c <= '9') {
			return (byte) (c - '0');
		}
		return (byte) (c - 'a' + 10);
	}

	static private byte b2a(final byte c) {
		if (0 <= c && c <= 9) {
			return (byte) (c + '0');
		}
		return (byte) (c - 10 + 'A');
	}

	public void dispose() {
		Util.bzero(this.passphrase);
	}

	@Override
	public void finalize() {
		this.dispose();
	}

	static KeyPair loadPPK(final JSch jsch, final byte[] buf) throws JSchException {
		byte[] pubkey = null;
		byte[] prvkey = null;
		int lines = 0;

		final Buffer buffer = new Buffer(buf);
		final java.util.Hashtable<String, String> v = new java.util.Hashtable<String, String>();

		while (true) {
			if (!parseHeader(buffer, v)) {
				break;
			}
		}

		final String typ = v.get("PuTTY-User-Key-File-2");
		if (typ == null) {
			return null;
		}

		lines = Integer.parseInt(v.get("Public-Lines"));
		pubkey = parseLines(buffer, lines);

		while (true) {
			if (!parseHeader(buffer, v)) {
				break;
			}
		}

		lines = Integer.parseInt(v.get("Private-Lines"));
		prvkey = parseLines(buffer, lines);

		while (true) {
			if (!parseHeader(buffer, v)) {
				break;
			}
		}

		prvkey = Util.fromBase64(prvkey, 0, prvkey.length);
		pubkey = Util.fromBase64(pubkey, 0, pubkey.length);

		KeyPair kpair = null;

		if (typ.equals("ssh-rsa")) {

			final Buffer _buf = new Buffer(pubkey);
			_buf.skip(pubkey.length);

			final int len = _buf.getInt();
			_buf.getByte(new byte[len]); // ssh-rsa
			final byte[] pub_array = new byte[_buf.getInt()];
			_buf.getByte(pub_array);
			final byte[] n_array = new byte[_buf.getInt()];
			_buf.getByte(n_array);

			kpair = new KeyPairRSA(jsch, n_array, pub_array, null);
		} else if (typ.equals("ssh-dss")) {
			final Buffer _buf = new Buffer(pubkey);
			_buf.skip(pubkey.length);

			final int len = _buf.getInt();
			_buf.getByte(new byte[len]); // ssh-dss

			final byte[] p_array = new byte[_buf.getInt()];
			_buf.getByte(p_array);
			final byte[] q_array = new byte[_buf.getInt()];
			_buf.getByte(q_array);
			final byte[] g_array = new byte[_buf.getInt()];
			_buf.getByte(g_array);
			final byte[] y_array = new byte[_buf.getInt()];
			_buf.getByte(y_array);

			kpair = new KeyPairDSA(jsch, p_array, q_array, g_array, y_array, null);
		} else {
			return null;
		}

		kpair.encrypted = !v.get("Encryption").equals("none");
		kpair.vendor = VENDOR_PUTTY;
		kpair.publicKeyComment = v.get("Comment");
		if (kpair.encrypted) {
			if (Session.checkCipher(JSch.getConfig("aes256-cbc"))) {
				try {
					final Class<?> c = Class.forName(JSch.getConfig("aes256-cbc"));
					kpair.cipher = (Cipher) c.newInstance();
					kpair.iv = new byte[kpair.cipher.getIVSize()];
				} catch (final Exception e) {
					throw new JSchException("The cipher 'aes256-cbc' is required, but it is not available.");
				}
			} else {
				throw new JSchException("The cipher 'aes256-cbc' is required, but it is not available.");
			}
			kpair.data = prvkey;
		} else {
			kpair.data = prvkey;
			kpair.parse(prvkey);
		}
		return kpair;
	}

	private static byte[] parseLines(final Buffer buffer, int lines) {
		final byte[] buf = buffer.buffer;
		int index = buffer.index;
		byte[] data = null;

		int i = index;
		while (lines-- > 0) {
			while (buf.length > i) {
				if (buf[i++] == 0x0d) {
					if (data == null) {
						data = new byte[i - index - 1];
						System.arraycopy(buf, index, data, 0, i - index - 1);
					} else {
						final byte[] tmp = new byte[data.length + i - index - 1];
						System.arraycopy(data, 0, tmp, 0, data.length);
						System.arraycopy(buf, index, tmp, data.length, i - index - 1);
						for (int j = 0; j < data.length; j++) {
							data[j] = 0; // clear
						}
						data = tmp;
					}
					break;
				}
			}
			if (buf[i] == 0x0a) {
				i++;
			}
			index = i;
		}

		if (data != null) {
			buffer.index = index;
		}

		return data;
	}

	private static boolean parseHeader(final Buffer buffer, final java.util.Hashtable<String, String> v) {
		final byte[] buf = buffer.buffer;
		int index = buffer.index;
		String key = null;
		String value = null;
		for (int i = index; i < buf.length; i++) {
			if (buf[i] == 0x0d) {
				break;
			}
			if (buf[i] == ':') {
				key = new String(buf, index, i - index);
				i++;
				if (i < buf.length && buf[i] == ' ') {
					i++;
				}
				index = i;
				break;
			}
		}

		if (key == null) {
			return false;
		}

		for (int i = index; i < buf.length; i++) {
			if (buf[i] == 0x0d) {
				value = new String(buf, index, i - index);
				i++;
				if (i < buf.length && buf[i] == 0x0a) {
					i++;
				}
				index = i;
				break;
			}
		}

		if (value != null) {
			v.put(key, value);
			buffer.index = index;
		}

		return value != null;
	}

	void copy(final KeyPair kpair) {
		this.publickeyblob = kpair.publickeyblob;
		this.vendor = kpair.vendor;
		this.publicKeyComment = kpair.publicKeyComment;
		this.cipher = kpair.cipher;
	}

	class ASN1Exception extends Exception {

		/**
		 *
		 */
		private static final long serialVersionUID = 2024082651727202925L;
	}

	class ASN1 {

		byte[] buf;
		int start;
		int length;

		ASN1(final byte[] buf) throws ASN1Exception {
			this(buf, 0, buf.length);
		}

		ASN1(final byte[] buf, final int start, final int length) throws ASN1Exception {
			this.buf = buf;
			this.start = start;
			this.length = length;
			if (start + length > buf.length) {
				throw new ASN1Exception();
			}
		}

		int getType() {
			return this.buf[this.start] & 0xff;
		}

		boolean isSEQUENCE() {
			return this.getType() == (0x30 & 0xff);
		}

		boolean isINTEGER() {
			return this.getType() == (0x02 & 0xff);
		}

		boolean isOBJECT() {
			return this.getType() == (0x06 & 0xff);
		}

		boolean isOCTETSTRING() {
			return this.getType() == (0x04 & 0xff);
		}

		private int getLength(final int[] indexp) {
			int index = indexp[0];
			int length = this.buf[index++] & 0xff;
			if ((length & 0x80) != 0) {
				int foo = length & 0x7f;
				length = 0;
				while (foo-- > 0) {
					length = (length << 8) + (this.buf[index++] & 0xff);
				}
			}
			indexp[0] = index;
			return length;
		}

		byte[] getContent() {
			final int[] indexp = new int[1];
			indexp[0] = this.start + 1;
			final int length = this.getLength(indexp);
			final int index = indexp[0];
			final byte[] tmp = new byte[length];
			System.arraycopy(this.buf, index, tmp, 0, tmp.length);
			return tmp;
		}

		ASN1[] getContents() throws ASN1Exception {
			final int typ = this.buf[this.start];
			final int[] indexp = new int[1];
			indexp[0] = this.start + 1;
			int length = this.getLength(indexp);
			if (typ == 0x05) {
				return new ASN1[0];
			}
			int index = indexp[0];
			final java.util.Vector<ASN1> values = new java.util.Vector<ASN1>();
			while (length > 0) {
				index++;
				length--;
				final int tmp = index;
				indexp[0] = index;
				final int l = this.getLength(indexp);
				index = indexp[0];
				length -= index - tmp;
				values.addElement(new ASN1(this.buf, tmp - 1, 1 + index - tmp + l));
				index += l;
				length -= l;
			}
			final ASN1[] result = new ASN1[values.size()];
			for (int i = 0; i < values.size(); i++) {
				result[i] = values.elementAt(i);
			}
			return result;
		}
	}
}
