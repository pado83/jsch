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

public class DHG1 extends KeyExchange {

	static final byte[] g = { 2 };
	static final byte[] p = {
			(byte) 0x00,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xC9, (byte) 0x0F, (byte) 0xDA, (byte) 0xA2, (byte) 0x21, (byte) 0x68, (byte) 0xC2, (byte) 0x34,
			(byte) 0xC4, (byte) 0xC6, (byte) 0x62, (byte) 0x8B, (byte) 0x80, (byte) 0xDC, (byte) 0x1C, (byte) 0xD1,
			(byte) 0x29, (byte) 0x02, (byte) 0x4E, (byte) 0x08, (byte) 0x8A, (byte) 0x67, (byte) 0xCC, (byte) 0x74,
			(byte) 0x02, (byte) 0x0B, (byte) 0xBE, (byte) 0xA6, (byte) 0x3B, (byte) 0x13, (byte) 0x9B, (byte) 0x22,
			(byte) 0x51, (byte) 0x4A, (byte) 0x08, (byte) 0x79, (byte) 0x8E, (byte) 0x34, (byte) 0x04, (byte) 0xDD,
			(byte) 0xEF, (byte) 0x95, (byte) 0x19, (byte) 0xB3, (byte) 0xCD, (byte) 0x3A, (byte) 0x43, (byte) 0x1B,
			(byte) 0x30, (byte) 0x2B, (byte) 0x0A, (byte) 0x6D, (byte) 0xF2, (byte) 0x5F, (byte) 0x14, (byte) 0x37,
			(byte) 0x4F, (byte) 0xE1, (byte) 0x35, (byte) 0x6D, (byte) 0x6D, (byte) 0x51, (byte) 0xC2, (byte) 0x45,
			(byte) 0xE4, (byte) 0x85, (byte) 0xB5, (byte) 0x76, (byte) 0x62, (byte) 0x5E, (byte) 0x7E, (byte) 0xC6,
			(byte) 0xF4, (byte) 0x4C, (byte) 0x42, (byte) 0xE9, (byte) 0xA6, (byte) 0x37, (byte) 0xED, (byte) 0x6B,
			(byte) 0x0B, (byte) 0xFF, (byte) 0x5C, (byte) 0xB6, (byte) 0xF4, (byte) 0x06, (byte) 0xB7, (byte) 0xED,
			(byte) 0xEE, (byte) 0x38, (byte) 0x6B, (byte) 0xFB, (byte) 0x5A, (byte) 0x89, (byte) 0x9F, (byte) 0xA5,
			(byte) 0xAE, (byte) 0x9F, (byte) 0x24, (byte) 0x11, (byte) 0x7C, (byte) 0x4B, (byte) 0x1F, (byte) 0xE6,
			(byte) 0x49, (byte) 0x28, (byte) 0x66, (byte) 0x51, (byte) 0xEC, (byte) 0xE6, (byte) 0x53, (byte) 0x81,
			(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF
	};

	private static final int SSH_MSG_KEXDH_INIT = 30;
	private static final int SSH_MSG_KEXDH_REPLY = 31;

	private int state;

	DH dh;

	byte[] V_S;
	byte[] V_C;
	byte[] I_S;
	byte[] I_C;

	byte[] e;

	private Buffer buf;
	private Packet packet;

	@Override
	public void init(final Session session,
			final byte[] V_S, final byte[] V_C, final byte[] I_S, final byte[] I_C) throws Exception {
		this.session = session;
		this.V_S = V_S;
		this.V_C = V_C;
		this.I_S = I_S;
		this.I_C = I_C;

		try {
			final Class<?> c = Class.forName(session.getConfig("sha-1"));
			this.sha = (HASH) (c.newInstance());
			this.sha.init();
		} catch (final Exception e) {
			System.err.println(e);
		}

		this.buf = new Buffer();
		this.packet = new Packet(this.buf);

		try {
			final Class<?> c = Class.forName(session.getConfig("dh"));
			this.dh = (DH) (c.newInstance());
			this.dh.init();
		} catch (final Exception e) {
			// System.err.println(e);
			throw e;
		}

		this.dh.setP(p);
		this.dh.setG(g);

		// The client responds with:
		// byte SSH_MSG_KEXDH_INIT(30)
		// mpint e <- g^x mod p
		// x is a random number (1 < x < (p-1)/2)

		this.e = this.dh.getE();

		this.packet.reset();
		this.buf.putByte((byte) SSH_MSG_KEXDH_INIT);
		this.buf.putMPInt(this.e);
		session.write(this.packet);

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"SSH_MSG_KEXDH_INIT sent");
			JSch.getLogger().log(Logger.INFO,
					"expecting SSH_MSG_KEXDH_REPLY");
		}

		this.state = SSH_MSG_KEXDH_REPLY;
	}

	@Override
	public boolean next(final Buffer _buf) throws Exception {
		int i, j;

		switch (this.state) {
			case SSH_MSG_KEXDH_REPLY:
				// The server responds with:
				// byte SSH_MSG_KEXDH_REPLY(31)
				// string server public host key and certificates (K_S)
				// mpint f
				// string signature of H
				j = _buf.getInt();
				j = _buf.getByte();
				j = _buf.getByte();
				if (j != 31) {
					System.err.println("type: must be 31 " + j);
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
				this.buf.putMPInt(this.e);
				this.buf.putMPInt(f);
				this.buf.putMPInt(this.K);
				final byte[] foo = new byte[this.buf.getLength()];
				this.buf.getByte(foo);
				this.sha.update(foo, 0, foo.length);
				this.H = this.sha.digest();
				// System.err.print("H -> "); //dump(H, 0, H.length);

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
}
