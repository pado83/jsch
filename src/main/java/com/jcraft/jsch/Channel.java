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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

public abstract class Channel implements Runnable {

	static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
	static final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
	static final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;

	static final int SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
	static final int SSH_OPEN_CONNECT_FAILED = 2;
	static final int SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3;
	static final int SSH_OPEN_RESOURCE_SHORTAGE = 4;

	static int index = 0;
	private static java.util.Vector pool = new java.util.Vector();

	static Channel getChannel(final String type) {
		if (type.equals("session")) {
			return new ChannelSession();
		}
		if (type.equals("shell")) {
			return new ChannelShell();
		}
		if (type.equals("exec")) {
			return new ChannelExec();
		}
		if (type.equals("x11")) {
			return new ChannelX11();
		}
		if (type.equals("auth-agent@openssh.com")) {
			return new ChannelAgentForwarding();
		}
		if (type.equals("direct-tcpip")) {
			return new ChannelDirectTCPIP();
		}
		if (type.equals("forwarded-tcpip")) {
			return new ChannelForwardedTCPIP();
		}
		if (type.equals("sftp")) {
			return new ChannelSftp();
		}
		if (type.equals("subsystem")) {
			return new ChannelSubsystem();
		}
		return null;
	}

	static Channel getChannel(final int id, final Session session) {
		synchronized (pool) {
			for (int i = 0; i < pool.size(); i++) {
				final Channel c = (Channel) (pool.elementAt(i));
				if (c.id == id && c.session == session) {
					return c;
				}
			}
		}
		return null;
	}

	static void del(final Channel c) {
		synchronized (pool) {
			pool.removeElement(c);
		}
	}

	int id;
	volatile int recipient = -1;
	protected byte[] type = Util.str2byte("foo");
	volatile int lwsize_max = 0x100000;
	volatile int lwsize = this.lwsize_max; // local initial window size
	volatile int lmpsize = 0x4000; // local maximum packet size

	volatile long rwsize = 0; // remote initial window size
	volatile int rmpsize = 0; // remote maximum packet size

	IO io = null;
	Thread thread = null;

	volatile boolean eof_local = false;
	volatile boolean eof_remote = false;

	volatile boolean close = false;
	volatile boolean connected = false;
	volatile boolean open_confirmation = false;

	volatile int exitstatus = -1;

	volatile int reply = 0;
	volatile int connectTimeout = 0;

	private Session session;

	int notifyme = 0;

	Channel() {
		synchronized (pool) {
			this.id = index++;
			pool.addElement(this);
		}
	}

	synchronized void setRecipient(final int foo) {
		this.recipient = foo;
		if (this.notifyme > 0) {
			this.notifyAll();
		}
	}

	int getRecipient() {
		return this.recipient;
	}

	void init() throws JSchException {}

	public void connect() throws JSchException {
		this.connect(0);
	}

	public void connect(final int connectTimeout) throws JSchException {
		this.connectTimeout = connectTimeout;
		try {
			this.sendChannelOpen();
			this.start();
		} catch (final Exception e) {
			this.connected = false;
			this.disconnect();
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			throw new JSchException(e.toString(), e);
		}
	}

	public void setXForwarding(final boolean foo) {}

	public void start() throws JSchException {}

	public boolean isEOF() {
		return this.eof_remote;
	}

	void getData(final Buffer buf) {
		this.setRecipient(buf.getInt());
		this.setRemoteWindowSize(buf.getUInt());
		this.setRemotePacketSize(buf.getInt());
	}

	public void setInputStream(final InputStream in) {
		this.io.setInputStream(in, false);
	}

	public void setInputStream(final InputStream in, final boolean dontclose) {
		this.io.setInputStream(in, dontclose);
	}

	public void setOutputStream(final OutputStream out) {
		this.io.setOutputStream(out, false);
	}

	public void setOutputStream(final OutputStream out, final boolean dontclose) {
		this.io.setOutputStream(out, dontclose);
	}

	public void setExtOutputStream(final OutputStream out) {
		this.io.setExtOutputStream(out, false);
	}

	public void setExtOutputStream(final OutputStream out, final boolean dontclose) {
		this.io.setExtOutputStream(out, dontclose);
	}

	public InputStream getInputStream() throws IOException {
		int max_input_buffer_size = 32 * 1024;
		try {
			max_input_buffer_size = Integer.parseInt(this.getSession().getConfig("max_input_buffer_size"));
		} catch (final Exception e) {}
		final PipedInputStream in = new MyPipedInputStream(
				32 * 1024, // this value should be customizable.
				max_input_buffer_size);
		final boolean resizable = 32 * 1024 < max_input_buffer_size;
		this.io.setOutputStream(new PassiveOutputStream(in, resizable), false);
		return in;
	}

	public InputStream getExtInputStream() throws IOException {
		int max_input_buffer_size = 32 * 1024;
		try {
			max_input_buffer_size = Integer.parseInt(this.getSession().getConfig("max_input_buffer_size"));
		} catch (final Exception e) {}
		final PipedInputStream in = new MyPipedInputStream(
				32 * 1024, // this value should be customizable.
				max_input_buffer_size);
		final boolean resizable = 32 * 1024 < max_input_buffer_size;
		this.io.setExtOutputStream(new PassiveOutputStream(in, resizable), false);
		return in;
	}

	public OutputStream getOutputStream() throws IOException {

		final Channel channel = this;
		final OutputStream out = new OutputStream() {

			private int dataLen = 0;
			private Buffer buffer = null;
			private Packet packet = null;
			private boolean closed = false;

			private synchronized void init() throws java.io.IOException {
				this.buffer = new Buffer(Channel.this.rmpsize);
				this.packet = new Packet(this.buffer);

				final byte[] _buf = this.buffer.buffer;
				if (_buf.length - (14 + 0) - Session.buffer_margin <= 0) {
					this.buffer = null;
					this.packet = null;
					throw new IOException("failed to initialize the channel.");
				}

			}

			byte[] b = new byte[1];

			@Override
			public void write(final int w) throws java.io.IOException {
				this.b[0] = (byte) w;
				this.write(this.b, 0, 1);
			}

			@Override
			public void write(final byte[] buf, int s, int l) throws java.io.IOException {
				if (this.packet == null) {
					this.init();
				}

				if (this.closed) {
					throw new java.io.IOException("Already closed");
				}

				final byte[] _buf = this.buffer.buffer;
				final int _bufl = _buf.length;
				while (l > 0) {
					int _l = l;
					if (l > _bufl - (14 + this.dataLen) - Session.buffer_margin) {
						_l = _bufl - (14 + this.dataLen) - Session.buffer_margin;
					}

					if (_l <= 0) {
						this.flush();
						continue;
					}

					System.arraycopy(buf, s, _buf, 14 + this.dataLen, _l);
					this.dataLen += _l;
					s += _l;
					l -= _l;
				}
			}

			@Override
			public void flush() throws java.io.IOException {
				if (this.closed) {
					throw new java.io.IOException("Already closed");
				}
				if (this.dataLen == 0) {
					return;
				}
				this.packet.reset();
				this.buffer.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
				this.buffer.putInt(Channel.this.recipient);
				this.buffer.putInt(this.dataLen);
				this.buffer.skip(this.dataLen);
				try {
					final int foo = this.dataLen;
					this.dataLen = 0;
					synchronized (channel) {
						if (!channel.close) {
							Channel.this.getSession().write(this.packet, channel, foo);
						}
					}
				} catch (final Exception e) {
					this.close();
					throw new java.io.IOException(e.toString());
				}

			}

			@Override
			public void close() throws java.io.IOException {
				if (this.packet == null) {
					try {
						this.init();
					} catch (final java.io.IOException e) {
						// close should be finished silently.
						return;
					}
				}
				if (this.closed) {
					return;
				}
				if (this.dataLen > 0) {
					this.flush();
				}
				channel.eof();
				this.closed = true;
			}
		};
		return out;
	}

	class MyPipedInputStream extends PipedInputStream {

		private int BUFFER_SIZE = 1024;
		private int max_buffer_size = this.BUFFER_SIZE;

		MyPipedInputStream() throws IOException {
			super();
		}

		MyPipedInputStream(final int size) throws IOException {
			super();
			this.buffer = new byte[size];
			this.BUFFER_SIZE = size;
			this.max_buffer_size = size;
		}

		MyPipedInputStream(final int size, final int max_buffer_size) throws IOException {
			this(size);
			this.max_buffer_size = max_buffer_size;
		}

		MyPipedInputStream(final PipedOutputStream out) throws IOException {
			super(out);
		}

		MyPipedInputStream(final PipedOutputStream out, final int size) throws IOException {
			super(out);
			this.buffer = new byte[size];
			this.BUFFER_SIZE = size;
		}

		/*
		 * TODO: We should have our own Piped[I/O]Stream implementation.
		 * Before accepting data, JDK's PipedInputStream will check the existence of
		 * reader thread, and if it is not alive, the stream will be closed.
		 * That behavior may cause the problem if multiple threads make access to it.
		 */
		public synchronized void updateReadSide() throws IOException {
			if (this.available() != 0) { // not empty
				return;
			}
			this.in = 0;
			this.out = 0;
			this.buffer[this.in++] = 0;
			this.read();
		}

		private int freeSpace() {
			int size = 0;
			if (this.out < this.in) {
				size = this.buffer.length - this.in;
			} else if (this.in < this.out) {
				if (this.in == -1) {
					size = this.buffer.length;
				} else {
					size = this.out - this.in;
				}
			}
			return size;
		}

		synchronized void checkSpace(final int len) throws IOException {
			final int size = this.freeSpace();
			if (size < len) {
				final int datasize = this.buffer.length - size;
				int foo = this.buffer.length;
				while ((foo - datasize) < len) {
					foo *= 2;
				}

				if (foo > this.max_buffer_size) {
					foo = this.max_buffer_size;
				}
				if ((foo - datasize) < len) {
					return;
				}

				final byte[] tmp = new byte[foo];
				if (this.out < this.in) {
					System.arraycopy(this.buffer, 0, tmp, 0, this.buffer.length);
				} else if (this.in < this.out) {
					if (this.in == -1) {} else {
						System.arraycopy(this.buffer, 0, tmp, 0, this.in);
						System.arraycopy(this.buffer, this.out,
								tmp, tmp.length - (this.buffer.length - this.out),
								(this.buffer.length - this.out));
						this.out = tmp.length - (this.buffer.length - this.out);
					}
				} else if (this.in == this.out) {
					System.arraycopy(this.buffer, 0, tmp, 0, this.buffer.length);
					this.in = this.buffer.length;
				}
				this.buffer = tmp;
			} else if (this.buffer.length == size && size > this.BUFFER_SIZE) {
				int i = size / 2;
				if (i < this.BUFFER_SIZE) {
					i = this.BUFFER_SIZE;
				}
				final byte[] tmp = new byte[i];
				this.buffer = tmp;
			}
		}
	}

	void setLocalWindowSizeMax(final int foo) {
		this.lwsize_max = foo;
	}

	void setLocalWindowSize(final int foo) {
		this.lwsize = foo;
	}

	void setLocalPacketSize(final int foo) {
		this.lmpsize = foo;
	}

	synchronized void setRemoteWindowSize(final long foo) {
		this.rwsize = foo;
	}

	synchronized void addRemoteWindowSize(final long foo) {
		this.rwsize += foo;
		if (this.notifyme > 0) {
			this.notifyAll();
		}
	}

	void setRemotePacketSize(final int foo) {
		this.rmpsize = foo;
	}

	@Override
	public void run() {}

	void write(final byte[] foo) throws IOException {
		this.write(foo, 0, foo.length);
	}

	void write(final byte[] foo, final int s, final int l) throws IOException {
		try {
			this.io.put(foo, s, l);
		} catch (final NullPointerException e) {}
	}

	void write_ext(final byte[] foo, final int s, final int l) throws IOException {
		try {
			this.io.put_ext(foo, s, l);
		} catch (final NullPointerException e) {}
	}

	void eof_remote() {
		this.eof_remote = true;
		try {
			this.io.out_close();
		} catch (final NullPointerException e) {}
	}

	void eof() {
		if (this.eof_local) {
			return;
		}
		this.eof_local = true;

		final int i = this.getRecipient();
		if (i == -1) {
			return;
		}

		try {
			final Buffer buf = new Buffer(100);
			final Packet packet = new Packet(buf);
			packet.reset();
			buf.putByte((byte) Session.SSH_MSG_CHANNEL_EOF);
			buf.putInt(i);
			synchronized (this) {
				if (!this.close) {
					this.getSession().write(packet);
				}
			}
		} catch (final Exception e) {
			// System.err.println("Channel.eof");
			// e.printStackTrace();
		}
		/*
		 * if(!isConnected()){ disconnect(); }
		 */
	}

	/*
	 * http://www1.ietf.org/internet-drafts/draft-ietf-secsh-connect-24.txt
	 * 
	 * 5.3 Closing a Channel
	 * When a party will no longer send more data to a channel, it SHOULD
	 * send SSH_MSG_CHANNEL_EOF.
	 * 
	 * byte SSH_MSG_CHANNEL_EOF
	 * uint32 recipient_channel
	 * 
	 * No explicit response is sent to this message. However, the
	 * application may send EOF to whatever is at the other end of the
	 * channel. Note that the channel remains open after this message, and
	 * more data may still be sent in the other direction. This message
	 * does not consume window space and can be sent even if no window space
	 * is available.
	 * 
	 * When either party wishes to terminate the channel, it sends
	 * SSH_MSG_CHANNEL_CLOSE. Upon receiving this message, a party MUST
	 * send back a SSH_MSG_CHANNEL_CLOSE unless it has already sent this
	 * message for the channel. The channel is considered closed for a
	 * party when it has both sent and received SSH_MSG_CHANNEL_CLOSE, and
	 * the party may then reuse the channel number. A party MAY send
	 * SSH_MSG_CHANNEL_CLOSE without having sent or received
	 * SSH_MSG_CHANNEL_EOF.
	 * 
	 * byte SSH_MSG_CHANNEL_CLOSE
	 * uint32 recipient_channel
	 * 
	 * This message does not consume window space and can be sent even if no
	 * window space is available.
	 * 
	 * It is recommended that any data sent before this message is delivered
	 * to the actual destination, if possible.
	 */

	void close() {
		if (this.close) {
			return;
		}
		this.close = true;
		this.eof_local = this.eof_remote = true;

		final int i = this.getRecipient();
		if (i == -1) {
			return;
		}

		try {
			final Buffer buf = new Buffer(100);
			final Packet packet = new Packet(buf);
			packet.reset();
			buf.putByte((byte) Session.SSH_MSG_CHANNEL_CLOSE);
			buf.putInt(i);
			synchronized (this) {
				this.getSession().write(packet);
			}
		} catch (final Exception e) {
			// e.printStackTrace();
		}
	}

	public boolean isClosed() {
		return this.close;
	}

	static void disconnect(final Session session) {
		Channel[] channels = null;
		int count = 0;
		synchronized (pool) {
			channels = new Channel[pool.size()];
			for (int i = 0; i < pool.size(); i++) {
				try {
					final Channel c = ((Channel) (pool.elementAt(i)));
					if (c.session == session) {
						channels[count++] = c;
					}
				} catch (final Exception e) {}
			}
		}
		for (int i = 0; i < count; i++) {
			channels[i].disconnect();
		}
	}

	public void disconnect() {
		// System.err.println(this+":disconnect "+io+" "+connected);
		// Thread.dumpStack();

		try {

			synchronized (this) {
				if (!this.connected) {
					return;
				}
				this.connected = false;
			}

			this.close();

			this.eof_remote = this.eof_local = true;

			this.thread = null;

			try {
				if (this.io != null) {
					this.io.close();
				}
			} catch (final Exception e) {
				// e.printStackTrace();
			}
			// io=null;
		} finally {
			Channel.del(this);
		}
	}

	public boolean isConnected() {
		final Session _session = this.session;
		if (_session != null) {
			return _session.isConnected() && this.connected;
		}
		return false;
	}

	public void sendSignal(final String signal) throws Exception {
		final RequestSignal request = new RequestSignal();
		request.setSignal(signal);
		request.request(this.getSession(), this);
	}

	// public String toString(){
	// return "Channel: type="+new String(type)+",id="+id+",recipient="+recipient+",window_size="+window_size+",packet_size="+packet_size;
	// }

	/*
	 * class OutputThread extends Thread{
	 * Channel c;
	 * OutputThread(Channel c){ this.c=c;}
	 * public void run(){c.output_thread();}
	 * }
	 */

	class PassiveInputStream extends MyPipedInputStream {

		PipedOutputStream out;

		PassiveInputStream(final PipedOutputStream out, final int size) throws IOException {
			super(out, size);
			this.out = out;
		}

		PassiveInputStream(final PipedOutputStream out) throws IOException {
			super(out);
			this.out = out;
		}

		@Override
		public void close() throws IOException {
			if (this.out != null) {
				this.out.close();
			}
			this.out = null;
		}
	}

	class PassiveOutputStream extends PipedOutputStream {

		private MyPipedInputStream _sink = null;

		PassiveOutputStream(final PipedInputStream in,
				final boolean resizable_buffer) throws IOException {
			super(in);
			if (resizable_buffer && (in instanceof MyPipedInputStream)) {
				this._sink = (MyPipedInputStream) in;
			}
		}

		@Override
		public void write(final int b) throws IOException {
			if (this._sink != null) {
				this._sink.checkSpace(1);
			}
			super.write(b);
		}

		@Override
		public void write(final byte[] b, final int off, final int len) throws IOException {
			if (this._sink != null) {
				this._sink.checkSpace(len);
			}
			super.write(b, off, len);
		}
	}

	void setExitStatus(final int status) {
		this.exitstatus = status;
	}

	public int getExitStatus() {
		return this.exitstatus;
	}

	void setSession(final Session session) {
		this.session = session;
	}

	public Session getSession() throws JSchException {
		final Session _session = this.session;
		if (_session == null) {
			throw new JSchException("session is not available");
		}
		return _session;
	}

	public int getId() {
		return this.id;
	}

	protected void sendOpenConfirmation() throws Exception {
		final Buffer buf = new Buffer(100);
		final Packet packet = new Packet(buf);
		packet.reset();
		buf.putByte((byte) SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
		buf.putInt(this.getRecipient());
		buf.putInt(this.id);
		buf.putInt(this.lwsize);
		buf.putInt(this.lmpsize);
		this.getSession().write(packet);
	}

	protected void sendOpenFailure(final int reasoncode) {
		try {
			final Buffer buf = new Buffer(100);
			final Packet packet = new Packet(buf);
			packet.reset();
			buf.putByte((byte) SSH_MSG_CHANNEL_OPEN_FAILURE);
			buf.putInt(this.getRecipient());
			buf.putInt(reasoncode);
			buf.putString(Util.str2byte("open failed"));
			buf.putString(Util.empty);
			this.getSession().write(packet);
		} catch (final Exception e) {}
	}

	protected Packet genChannelOpenPacket() {
		final Buffer buf = new Buffer(100);
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
		return packet;
	}

	protected void sendChannelOpen() throws Exception {
		final Session _session = this.getSession();
		if (!_session.isConnected()) {
			throw new JSchException("session is down");
		}

		final Packet packet = this.genChannelOpenPacket();
		_session.write(packet);

		int retry = 2000;
		final long start = System.currentTimeMillis();
		final long timeout = this.connectTimeout;
		if (timeout != 0L) {
			retry = 1;
		}
		synchronized (this) {
			while (this.getRecipient() == -1 &&
					_session.isConnected() &&
					retry > 0) {
				if (timeout > 0L) {
					if ((System.currentTimeMillis() - start) > timeout) {
						retry = 0;
						continue;
					}
				}
				try {
					final long t = timeout == 0L ? 10L : timeout;
					this.notifyme = 1;
					this.wait(t);
				} catch (final java.lang.InterruptedException e) {} finally {
					this.notifyme = 0;
				}
				retry--;
			}
		}
		if (!_session.isConnected()) {
			throw new JSchException("session is down");
		}
		if (this.getRecipient() == -1) { // timeout
			throw new JSchException("channel is not opened.");
		}
		if (this.open_confirmation == false) { // SSH_MSG_CHANNEL_OPEN_FAILURE
			throw new JSchException("channel is not opened.");
		}
		this.connected = true;
	}
}
