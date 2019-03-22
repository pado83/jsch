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

public class DHGEX extends KeyExchange {

	private static final int SSH_MSG_KEX_DH_GEX_GROUP = 31;
	private static final int SSH_MSG_KEX_DH_GEX_INIT = 32;
	private static final int SSH_MSG_KEX_DH_GEX_REPLY = 33;
	private static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;

	static int min = 1024;
	static int preferred = 1024;
	int max = 1024;

	private int state;

	DH dh;

	byte[] V_S;
	byte[] V_C;
	byte[] I_S;
	byte[] I_C;

	private Buffer buf;
	private Packet packet;

	private byte[] p;
	private byte[] g;
	private byte[] e;

	protected String hash = "sha-1";

	@Override
	public void init(final Session session,
			final byte[] V_S, final byte[] V_C, final byte[] I_S, final byte[] I_C) throws Exception {
		this.session = session;
		this.V_S = V_S;
		this.V_C = V_C;
		this.I_S = I_S;
		this.I_C = I_C;

		try {
			final Class c = Class.forName(session.getConfig(this.hash));
			this.sha = (HASH) (c.newInstance());
			this.sha.init();
		} catch (final Exception e) {
			System.err.println(e);
		}

		this.buf = new Buffer();
		this.packet = new Packet(this.buf);

		try {
			final Class c = Class.forName(session.getConfig("dh"));
			// Since JDK8, SunJCE has lifted the keysize restrictions
			// from 1024 to 2048 for DH.
			preferred = this.max = this.check2048(c, this.max);
			this.dh = (com.jcraft.jsch.DH) (c.newInstance());
			this.dh.init();
		} catch (final Exception e) {
			throw e;
		}

		this.packet.reset();
		this.buf.putByte((byte) SSH_MSG_KEX_DH_GEX_REQUEST);
		this.buf.putInt(min);
		this.buf.putInt(preferred);
		this.buf.putInt(this.max);
		session.write(this.packet);

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"SSH_MSG_KEX_DH_GEX_REQUEST(" + min + "<" + preferred + "<" + this.max + ") sent");
			JSch.getLogger().log(Logger.INFO,
					"expecting SSH_MSG_KEX_DH_GEX_GROUP");
		}

		this.state = SSH_MSG_KEX_DH_GEX_GROUP;
	}

	@Override
	public boolean next(final Buffer _buf) throws Exception {
		int i, j;
		switch (this.state) {
			case SSH_MSG_KEX_DH_GEX_GROUP:
				// byte SSH_MSG_KEX_DH_GEX_GROUP(31)
				// mpint p, safe prime
				// mpint g, generator for subgroup in GF (p)
				_buf.getInt();
				_buf.getByte();
				j = _buf.getByte();
				if (j != SSH_MSG_KEX_DH_GEX_GROUP) {
					System.err.println("type: must be SSH_MSG_KEX_DH_GEX_GROUP " + j);
					return false;
				}

				this.p = _buf.getMPInt();
				this.g = _buf.getMPInt();

				this.dh.setP(this.p);
				this.dh.setG(this.g);
				// The client responds with:
				// byte SSH_MSG_KEX_DH_GEX_INIT(32)
				// mpint e <- g^x mod p
				// x is a random number (1 < x < (p-1)/2)

				this.e = this.dh.getE();

				this.packet.reset();
				this.buf.putByte((byte) SSH_MSG_KEX_DH_GEX_INIT);
				this.buf.putMPInt(this.e);
				this.session.write(this.packet);

				if (JSch.getLogger().isEnabled(Logger.INFO)) {
					JSch.getLogger().log(Logger.INFO,
							"SSH_MSG_KEX_DH_GEX_INIT sent");
					JSch.getLogger().log(Logger.INFO,
							"expecting SSH_MSG_KEX_DH_GEX_REPLY");
				}

				this.state = SSH_MSG_KEX_DH_GEX_REPLY;
				return true;
			// break;

			case SSH_MSG_KEX_DH_GEX_REPLY:
				// The server responds with:
				// byte SSH_MSG_KEX_DH_GEX_REPLY(33)
				// string server public host key and certificates (K_S)
				// mpint f
				// string signature of H
				j = _buf.getInt();
				j = _buf.getByte();
				j = _buf.getByte();
				if (j != SSH_MSG_KEX_DH_GEX_REPLY) {
					System.err.println("type: must be SSH_MSG_KEX_DH_GEX_REPLY " + j);
					return false;
				}

				this.K_S = _buf.getString();

				final byte[] f = _buf.getMPInt();
				final byte[] sig_of_H = _buf.getString();

				this.dh.setF(f);

				this.dh.checkRange();

				this.K = this.normalize(this.dh.getK());

				// The hash H is computed as the HASH hash of the concatenation of the
				// following:
				// string V_C, the client's version string (CR and NL excluded)
				// string V_S, the server's version string (CR and NL excluded)
				// string I_C, the payload of the client's SSH_MSG_KEXINIT
				// string I_S, the payload of the server's SSH_MSG_KEXINIT
				// string K_S, the host key
				// uint32 min, minimal size in bits of an acceptable group
				// uint32 n, preferred size in bits of the group the server should send
				// uint32 max, maximal size in bits of an acceptable group
				// mpint p, safe prime
				// mpint g, generator for subgroup
				// mpint e, exchange value sent by the client
				// mpint f, exchange value sent by the server
				// mpint K, the shared secret
				// This value is called the exchange hash, and it is used to authenti-
				// cate the key exchange.

				this.buf.reset();
				this.buf.putString(this.V_C);
				this.buf.putString(this.V_S);
				this.buf.putString(this.I_C);
				this.buf.putString(this.I_S);
				this.buf.putString(this.K_S);
				this.buf.putInt(min);
				this.buf.putInt(preferred);
				this.buf.putInt(this.max);
				this.buf.putMPInt(this.p);
				this.buf.putMPInt(this.g);
				this.buf.putMPInt(this.e);
				this.buf.putMPInt(f);
				this.buf.putMPInt(this.K);

				final byte[] foo = new byte[this.buf.getLength()];
				this.buf.getByte(foo);
				this.sha.update(foo, 0, foo.length);

				this.H = this.sha.digest();

				// System.err.print("H -> "); dump(H, 0, H.length);

				i = 0;
				j = 0;
				j = ((this.K_S[i++] << 24) & 0xff000000) | ((this.K_S[i++] << 16) & 0x00ff0000) |
						((this.K_S[i++] << 8) & 0x0000ff00) | ((this.K_S[i++]) & 0x000000ff);
				final String alg = Util.byte2str(this.K_S, i, j);
				i += j;

				final boolean result = this.verify(alg, this.K_S, i, sig_of_H);

				this.state = STATE_END;
				return result;
		}
		return false;
	}

	@Override
	public int getState() {
		return this.state;
	}

	protected int check2048(final Class c, int _max) throws Exception {
		final DH dh = (com.jcraft.jsch.DH) (c.newInstance());
		dh.init();
		final byte[] foo = new byte[257];
		foo[1] = (byte) 0xdd;
		foo[256] = 0x73;
		dh.setP(foo);
		final byte[] bar = { (byte) 0x02 };
		dh.setG(bar);
		try {
			dh.getE();
			_max = 2048;
		} catch (final Exception e) {}
		return _max;
	}
}
