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

import java.io.InputStream;
import java.io.OutputStream;

public class ChannelDirectTCPIP extends Channel {

	static private final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	static private final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;
	static private final byte[] _type = Util.str2byte("direct-tcpip");
	String host;
	int port;

	String originator_IP_address = "127.0.0.1";
	int originator_port = 0;

	ChannelDirectTCPIP() {
		super();
		this.type = _type;
		this.setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
	}

	@Override
	void init() {
		this.io = new IO();
	}

	@Override
	public void connect(final int connectTimeout) throws JSchException {
		this.connectTimeout = connectTimeout;
		try {
			final Session _session = this.getSession();
			if (!_session.isConnected()) {
				throw new JSchException("session is down");
			}

			if (this.io.in != null) {
				this.thread = new Thread(this);
				this.thread.setName("DirectTCPIP thread " + _session.getHost());
				if (_session.daemon_thread) {
					this.thread.setDaemon(_session.daemon_thread);
				}
				this.thread.start();
			} else {
				this.sendChannelOpen();
			}
		} catch (final Exception e) {
			this.io.close();
			this.io = null;
			Channel.del(this);
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
		}
	}

	@Override
	public void run() {

		try {
			this.sendChannelOpen();

			final Buffer buf = new Buffer(this.rmpsize);
			final Packet packet = new Packet(buf);
			final Session _session = this.getSession();
			int i = 0;

			while (this.isConnected() &&
					this.thread != null &&
					this.io != null &&
					this.io.in != null) {
				i = this.io.in.read(buf.buffer,
						14,
						buf.buffer.length - 14
								- Session.buffer_margin);
				if (i <= 0) {
					this.eof();
					break;
				}
				packet.reset();
				buf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
				buf.putInt(this.recipient);
				buf.putInt(i);
				buf.skip(i);
				synchronized (this) {
					if (this.close) {
						break;
					}
					_session.write(packet, this, i);
				}
			}
		} catch (final Exception e) {
			// Whenever an exception is thrown by sendChannelOpen(),
			// 'connected' is false.
			if (!this.connected) {
				this.connected = true;
			}
			this.disconnect();
			return;
		}

		this.eof();
		this.disconnect();
	}

	@Override
	public void setInputStream(final InputStream in) {
		this.io.setInputStream(in);
	}

	@Override
	public void setOutputStream(final OutputStream out) {
		this.io.setOutputStream(out);
	}

	public void setHost(final String host) {
		this.host = host;
	}

	public void setPort(final int port) {
		this.port = port;
	}

	public void setOrgIPAddress(final String foo) {
		this.originator_IP_address = foo;
	}

	public void setOrgPort(final int foo) {
		this.originator_port = foo;
	}

	@Override
	protected Packet genChannelOpenPacket() {
		final Buffer buf = new Buffer(50 + // 6 + 4*8 + 12
				this.host.length() + this.originator_IP_address.length() +
				Session.buffer_margin);
		final Packet packet = new Packet(buf);
		// byte SSH_MSG_CHANNEL_OPEN(90)
		// string channel type //
		// uint32 sender channel // 0
		// uint32 initial window size // 0x100000(65536)
		// uint32 maxmum packet size // 0x4000(16384)
		packet.reset();
		buf.putByte((byte) 90);
		buf.putString(this.type);
		buf.putInt(this.id);
		buf.putInt(this.lwsize);
		buf.putInt(this.lmpsize);
		buf.putString(Util.str2byte(this.host));
		buf.putInt(this.port);
		buf.putString(Util.str2byte(this.originator_IP_address));
		buf.putInt(this.originator_port);
		return packet;
	}
}
