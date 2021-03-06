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

import java.net.Socket;
import java.util.Hashtable;

class ChannelX11 extends Channel {

	static private final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	static private final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

	static private final int TIMEOUT = 10 * 1000;

	private static String host = "127.0.0.1";
	private static int port = 6000;

	private boolean init = true;

	static byte[] cookie = null;
	private static byte[] cookie_hex = null;

	private static java.util.Hashtable<Session, byte[]> faked_cookie_pool = new Hashtable<Session, byte[]>();
	private static java.util.Hashtable<Session, byte[]> faked_cookie_hex_pool = new Hashtable<Session, byte[]>();

	private static byte[] table = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
			0x61, 0x62, 0x63, 0x64, 0x65, 0x66 };

	private Socket socket = null;

	static int revtable(final byte foo) {
		for (int i = 0; i < table.length; i++) {
			if (table[i] == foo) {
				return i;
			}
		}
		return 0;
	}

	static void setCookie(final String foo) {
		cookie_hex = Util.str2byte(foo);
		cookie = new byte[16];
		for (int i = 0; i < 16; i++) {
			cookie[i] = (byte) (revtable(cookie_hex[i * 2]) << 4 & 0xf0 |
					revtable(cookie_hex[i * 2 + 1]) & 0xf);
		}
	}

	static void setHost(final String foo) {
		host = foo;
	}

	static void setPort(final int foo) {
		port = foo;
	}

	static byte[] getFakedCookie(final Session session) {
		synchronized (faked_cookie_hex_pool) {
			byte[] foo = faked_cookie_hex_pool.get(session);
			if (foo == null) {
				final Random random = Session.random;
				foo = new byte[16];
				synchronized (random) {
					random.fill(foo, 0, 16);
				}
				/*
				 * System.err.print("faked_cookie: ");
				 * for(int i=0; i<foo.length; i++){
				 * System.err.print(Integer.toHexString(foo[i]&0xff)+":");
				 * }
				 * System.err.println("");
				 */
				faked_cookie_pool.put(session, foo);
				final byte[] bar = new byte[32];
				for (int i = 0; i < 16; i++) {
					bar[2 * i] = table[foo[i] >>> 4 & 0xf];
					bar[2 * i + 1] = table[foo[i] & 0xf];
				}
				faked_cookie_hex_pool.put(session, bar);
				foo = bar;
			}
			return foo;
		}
	}

	static void removeFakedCookie(final Session session) {
		synchronized (faked_cookie_hex_pool) {
			faked_cookie_hex_pool.remove(session);
			faked_cookie_pool.remove(session);
		}
	}

	ChannelX11() {
		super();

		this.setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);

		this.type = Util.str2byte("x11");

		this.connected = true;
		/*
		 * try{
		 * socket=Util.createSocket(host, port, TIMEOUT);
		 * socket.setTcpNoDelay(true);
		 * io=new IO();
		 * io.setInputStream(socket.getInputStream());
		 * io.setOutputStream(socket.getOutputStream());
		 * }
		 * catch(Exception e){
		 * //System.err.println(e);
		 * }
		 */
	}

	@Override
	public void run() {

		try {
			this.socket = Util.createSocket(host, port, TIMEOUT);
			this.socket.setTcpNoDelay(true);
			this.io = new IO();
			this.io.setInputStream(this.socket.getInputStream());
			this.io.setOutputStream(this.socket.getOutputStream());
			this.sendOpenConfirmation();
		} catch (final Exception e) {
			this.sendOpenFailure(SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
			this.close = true;
			this.disconnect();
			return;
		}

		this.thread = Thread.currentThread();
		final Buffer buf = new Buffer(this.rmpsize);
		final Packet packet = new Packet(buf);
		int i = 0;
		try {
			while (this.thread != null &&
					this.io != null &&
					this.io.in != null) {
				i = this.io.in.read(buf.buffer,
						14,
						buf.buffer.length - 14 - Session.buffer_margin);
				if (i <= 0) {
					this.eof();
					break;
				}
				if (this.close) {
					break;
				}
				packet.reset();
				buf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
				buf.putInt(this.recipient);
				buf.putInt(i);
				buf.skip(i);
				this.getSession().write(packet, this, i);
			}
		} catch (final Exception e) {
			// System.err.println(e);
		}
		this.disconnect();
	}

	private byte[] cache = new byte[0];

	private byte[] addCache(final byte[] foo, final int s, final int l) {
		final byte[] bar = new byte[this.cache.length + l];
		System.arraycopy(foo, s, bar, this.cache.length, l);
		if (this.cache.length > 0) {
			System.arraycopy(this.cache, 0, bar, 0, this.cache.length);
		}
		this.cache = bar;
		return this.cache;
	}

	@Override
	void write(byte[] foo, int s, int l) throws java.io.IOException {
		// if(eof_local)return;

		if (this.init) {

			Session _session = null;
			try {
				_session = this.getSession();
			} catch (final JSchException e) {
				throw new java.io.IOException(e.toString());
			}

			foo = this.addCache(foo, s, l);
			s = 0;
			l = foo.length;

			if (l < 9) {
				return;
			}

			int plen = (foo[s + 6] & 0xff) * 256 + (foo[s + 7] & 0xff);
			int dlen = (foo[s + 8] & 0xff) * 256 + (foo[s + 9] & 0xff);

			if ((foo[s] & 0xff) == 0x42) {} else if ((foo[s] & 0xff) == 0x6c) {
				plen = plen >>> 8 & 0xff | plen << 8 & 0xff00;
				dlen = dlen >>> 8 & 0xff | dlen << 8 & 0xff00;
			} else {
				// ??
			}

			if (l < 12 + plen + (-plen & 3) + dlen) {
				return;
			}

			final byte[] bar = new byte[dlen];
			System.arraycopy(foo, s + 12 + plen + (-plen & 3), bar, 0, dlen);
			byte[] faked_cookie = null;

			synchronized (faked_cookie_pool) {
				faked_cookie = faked_cookie_pool.get(_session);
			}

			/*
			 * System.err.print("faked_cookie: ");
			 * for(int i=0; i<faked_cookie.length; i++){
			 * System.err.print(Integer.toHexString(faked_cookie[i]&0xff)+":");
			 * }
			 * System.err.println("");
			 * System.err.print("bar: ");
			 * for(int i=0; i<bar.length; i++){
			 * System.err.print(Integer.toHexString(bar[i]&0xff)+":");
			 * }
			 * System.err.println("");
			 */

			if (equals(bar, faked_cookie)) {
				if (cookie != null) {
					System.arraycopy(cookie, 0, foo, s + 12 + plen + (-plen & 3), dlen);
				}
			} else {
				// System.err.println("wrong cookie");
				this.thread = null;
				this.eof();
				this.io.close();
				this.disconnect();
			}
			this.init = false;
			this.io.put(foo, s, l);
			this.cache = null;
			return;
		}
		this.io.put(foo, s, l);
	}

	private static boolean equals(final byte[] foo, final byte[] bar) {
		if (foo.length != bar.length) {
			return false;
		}
		for (int i = 0; i < foo.length; i++) {
			if (foo[i] != bar[i]) {
				return false;
			}
		}
		return true;
	}
}
