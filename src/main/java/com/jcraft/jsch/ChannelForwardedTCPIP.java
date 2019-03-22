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

import java.io.PipedOutputStream;
import java.net.Socket;
import java.util.Vector;

public class ChannelForwardedTCPIP extends Channel {

	private static Vector pool = new Vector();

	static private final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	// static private final int LOCAL_WINDOW_SIZE_MAX=0x100000;
	static private final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

	static private final int TIMEOUT = 10 * 1000;

	private Socket socket = null;
	private ForwardedTCPIPDaemon daemon = null;
	private Config config = null;

	ChannelForwardedTCPIP() {
		super();
		this.setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
		this.io = new IO();
		this.connected = true;
	}

	@Override
	public void run() {
		try {
			if (this.config instanceof ConfigDaemon) {
				final ConfigDaemon _config = (ConfigDaemon) this.config;
				final Class c = Class.forName(_config.target);
				this.daemon = (ForwardedTCPIPDaemon) c.newInstance();

				final PipedOutputStream out = new PipedOutputStream();
				this.io.setInputStream(new PassiveInputStream(out, 32 * 1024), false);

				this.daemon.setChannel(this, this.getInputStream(), out);
				this.daemon.setArg(_config.arg);
				new Thread(this.daemon).start();
			} else {
				final ConfigLHost _config = (ConfigLHost) this.config;
				this.socket = (_config.factory == null) ? Util.createSocket(_config.target, _config.lport, TIMEOUT) : _config.factory.createSocket(_config.target, _config.lport);
				this.socket.setTcpNoDelay(true);
				this.io.setInputStream(this.socket.getInputStream());
				this.io.setOutputStream(this.socket.getOutputStream());
			}
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
			final Session _session = this.getSession();
			while (this.thread != null &&
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
			// System.err.println(e);
		}
		// thread=null;
		// eof();
		this.disconnect();
	}

	@Override
	void getData(final Buffer buf) {
		this.setRecipient(buf.getInt());
		this.setRemoteWindowSize(buf.getUInt());
		this.setRemotePacketSize(buf.getInt());
		final byte[] addr = buf.getString();
		final int port = buf.getInt();
		final byte[] orgaddr = buf.getString();
		final int orgport = buf.getInt();

		/*
		 * System.err.println("addr: "+Util.byte2str(addr));
		 * System.err.println("port: "+port);
		 * System.err.println("orgaddr: "+Util.byte2str(orgaddr));
		 * System.err.println("orgport: "+orgport);
		 */

		Session _session = null;
		try {
			_session = this.getSession();
		} catch (final JSchException e) {
			// session has been already down.
		}

		this.config = getPort(_session, Util.byte2str(addr), port);
		if (this.config == null) {
			this.config = getPort(_session, null, port);
		}

		if (this.config == null) {
			if (JSch.getLogger().isEnabled(Logger.ERROR)) {
				JSch.getLogger().log(Logger.ERROR,
						"ChannelForwardedTCPIP: " + Util.byte2str(addr) + ":" + port + " is not registered.");
			}
		}
	}

	private static Config getPort(final Session session, final String address_to_bind, final int rport) {
		synchronized (pool) {
			for (int i = 0; i < pool.size(); i++) {
				final Config bar = (Config) (pool.elementAt(i));
				if (bar.session != session) {
					continue;
				}
				if (bar.rport != rport) {
					if (bar.rport != 0 || bar.allocated_rport != rport) {
						continue;
					}
				}
				if (address_to_bind != null &&
						!bar.address_to_bind.equals(address_to_bind)) {
					continue;
				}
				return bar;
			}
			return null;
		}
	}

	static String[] getPortForwarding(final Session session) {
		final Vector foo = new Vector();
		synchronized (pool) {
			for (int i = 0; i < pool.size(); i++) {
				final Config config = (Config) (pool.elementAt(i));
				if (config instanceof ConfigDaemon) {
					foo.addElement(config.allocated_rport + ":" + config.target + ":");
				} else {
					foo.addElement(config.allocated_rport + ":" + config.target + ":" + ((ConfigLHost) config).lport);
				}
			}
		}
		final String[] bar = new String[foo.size()];
		for (int i = 0; i < foo.size(); i++) {
			bar[i] = (String) (foo.elementAt(i));
		}
		return bar;
	}

	static String normalize(final String address) {
		if (address == null) {
			return "localhost";
		} else if (address.length() == 0 || address.equals("*")) {
			return "";
		} else {
			return address;
		}
	}

	static void addPort(final Session session, final String _address_to_bind,
			final int port, final int allocated_port, final String target, final int lport, final SocketFactory factory) throws JSchException {
		final String address_to_bind = normalize(_address_to_bind);
		synchronized (pool) {
			if (getPort(session, address_to_bind, port) != null) {
				throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
			}
			final ConfigLHost config = new ConfigLHost();
			config.session = session;
			config.rport = port;
			config.allocated_rport = allocated_port;
			config.target = target;
			config.lport = lport;
			config.address_to_bind = address_to_bind;
			config.factory = factory;
			pool.addElement(config);
		}
	}

	static void addPort(final Session session, final String _address_to_bind,
			final int port, final int allocated_port, final String daemon, final Object[] arg) throws JSchException {
		final String address_to_bind = normalize(_address_to_bind);
		synchronized (pool) {
			if (getPort(session, address_to_bind, port) != null) {
				throw new JSchException("PortForwardingR: remote port " + port + " is already registered.");
			}
			final ConfigDaemon config = new ConfigDaemon();
			config.session = session;
			config.rport = port;
			config.allocated_rport = port;
			config.target = daemon;
			config.arg = arg;
			config.address_to_bind = address_to_bind;
			pool.addElement(config);
		}
	}

	static void delPort(final ChannelForwardedTCPIP c) {
		Session _session = null;
		try {
			_session = c.getSession();
		} catch (final JSchException e) {
			// session has been already down.
		}
		if (_session != null && c.config != null) {
			delPort(_session, c.config.rport);
		}
	}

	static void delPort(final Session session, final int rport) {
		delPort(session, null, rport);
	}

	static void delPort(final Session session, String address_to_bind, final int rport) {
		synchronized (pool) {
			Config foo = getPort(session, normalize(address_to_bind), rport);
			if (foo == null) {
				foo = getPort(session, null, rport);
			}
			if (foo == null) {
				return;
			}
			pool.removeElement(foo);
			if (address_to_bind == null) {
				address_to_bind = foo.address_to_bind;
			}
			if (address_to_bind == null) {
				address_to_bind = "0.0.0.0";
			}
		}

		final Buffer buf = new Buffer(100); // ??
		final Packet packet = new Packet(buf);

		try {
			// byte SSH_MSG_GLOBAL_REQUEST 80
			// string "cancel-tcpip-forward"
			// boolean want_reply
			// string address_to_bind (e.g. "127.0.0.1")
			// uint32 port number to bind
			packet.reset();
			buf.putByte((byte) 80/* SSH_MSG_GLOBAL_REQUEST */);
			buf.putString(Util.str2byte("cancel-tcpip-forward"));
			buf.putByte((byte) 0);
			buf.putString(Util.str2byte(address_to_bind));
			buf.putInt(rport);
			session.write(packet);
		} catch (final Exception e) {
			// throw new JSchException(e.toString());
		}
	}

	static void delPort(final Session session) {
		int[] rport = null;
		int count = 0;
		synchronized (pool) {
			rport = new int[pool.size()];
			for (int i = 0; i < pool.size(); i++) {
				final Config config = (Config) (pool.elementAt(i));
				if (config.session == session) {
					rport[count++] = config.rport; // ((Integer)bar[1]).intValue();
				}
			}
		}
		for (int i = 0; i < count; i++) {
			delPort(session, rport[i]);
		}
	}

	public int getRemotePort() {
		return (this.config != null ? this.config.rport : 0);
	}

	private void setSocketFactory(final SocketFactory factory) {
		if (this.config != null && (this.config instanceof ConfigLHost)) {
			((ConfigLHost) this.config).factory = factory;
		}
	}

	static abstract class Config {

		Session session;
		int rport;
		int allocated_rport;
		String address_to_bind;
		String target;
	}

	static class ConfigDaemon extends Config {

		Object[] arg;
	}

	static class ConfigLHost extends Config {

		int lport;
		SocketFactory factory;
	}
}
