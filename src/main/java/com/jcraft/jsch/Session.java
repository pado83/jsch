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
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Vector;

public class Session implements Runnable {

	// http://ietf.org/internet-drafts/draft-ietf-secsh-assignednumbers-01.txt
	static final int SSH_MSG_DISCONNECT = 1;
	static final int SSH_MSG_IGNORE = 2;
	static final int SSH_MSG_UNIMPLEMENTED = 3;
	static final int SSH_MSG_DEBUG = 4;
	static final int SSH_MSG_SERVICE_REQUEST = 5;
	static final int SSH_MSG_SERVICE_ACCEPT = 6;
	static final int SSH_MSG_KEXINIT = 20;
	static final int SSH_MSG_NEWKEYS = 21;
	static final int SSH_MSG_KEXDH_INIT = 30;
	static final int SSH_MSG_KEXDH_REPLY = 31;
	static final int SSH_MSG_KEX_DH_GEX_GROUP = 31;
	static final int SSH_MSG_KEX_DH_GEX_INIT = 32;
	static final int SSH_MSG_KEX_DH_GEX_REPLY = 33;
	static final int SSH_MSG_KEX_DH_GEX_REQUEST = 34;
	static final int SSH_MSG_GLOBAL_REQUEST = 80;
	static final int SSH_MSG_REQUEST_SUCCESS = 81;
	static final int SSH_MSG_REQUEST_FAILURE = 82;
	static final int SSH_MSG_CHANNEL_OPEN = 90;
	static final int SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91;
	static final int SSH_MSG_CHANNEL_OPEN_FAILURE = 92;
	static final int SSH_MSG_CHANNEL_WINDOW_ADJUST = 93;
	static final int SSH_MSG_CHANNEL_DATA = 94;
	static final int SSH_MSG_CHANNEL_EXTENDED_DATA = 95;
	static final int SSH_MSG_CHANNEL_EOF = 96;
	static final int SSH_MSG_CHANNEL_CLOSE = 97;
	static final int SSH_MSG_CHANNEL_REQUEST = 98;
	static final int SSH_MSG_CHANNEL_SUCCESS = 99;
	static final int SSH_MSG_CHANNEL_FAILURE = 100;

	private static final int PACKET_MAX_SIZE = 256 * 1024;

	private byte[] V_S; // server version
	private byte[] V_C = Util.str2byte("SSH-2.0-JSCH-" + JSch.VERSION); // client version

	private byte[] I_C; // the payload of the client's SSH_MSG_KEXINIT
	private byte[] I_S; // the payload of the server's SSH_MSG_KEXINIT
	private byte[] session_id;

	private byte[] IVc2s;
	private byte[] IVs2c;
	private byte[] Ec2s;
	private byte[] Es2c;
	private byte[] MACc2s;
	private byte[] MACs2c;

	private int seqi = 0;
	private int seqo = 0;

	String[] guess = null;
	private Cipher s2ccipher;
	private Cipher c2scipher;
	private MAC s2cmac;
	private MAC c2smac;
	// private byte[] mac_buf;
	private byte[] s2cmac_result1;
	private byte[] s2cmac_result2;

	private Compression deflater;
	private Compression inflater;

	private IO io;
	private Socket socket;
	private int timeout = 0;

	private volatile boolean isConnected = false;

	private boolean isAuthed = false;

	private Thread connectThread = null;
	private final Object lock = new Object();

	boolean x11_forwarding = false;
	boolean agent_forwarding = false;

	InputStream in = null;
	OutputStream out = null;

	static Random random;

	Buffer buf;
	Packet packet;

	SocketFactory socket_factory = null;

	static final int buffer_margin = 32 + // maximum padding length
			64 + // maximum mac length
			32; // margin for deflater; deflater may inflate data

	private java.util.Hashtable<String, String> config = null;

	private Proxy proxy = null;
	private UserInfo userinfo;

	private String hostKeyAlias = null;
	private int serverAliveInterval = 0;
	private int serverAliveCountMax = 1;

	private IdentityRepository identityRepository = null;
	private HostKeyRepository hostkeyRepository = null;

	protected boolean daemon_thread = false;

	private long kex_start_time = 0L;

	int max_auth_tries = 6;
	int auth_failures = 0;

	String host = "127.0.0.1";
	String org_host = "127.0.0.1";
	int port = 22;

	String username = null;
	byte[] password = null;

	JSch jsch;

	Session(final JSch jsch, final String username, final String host, final int port) throws JSchException {
		super();
		this.jsch = jsch;
		this.buf = new Buffer();
		this.packet = new Packet(this.buf);
		this.username = username;
		this.org_host = this.host = host;
		this.port = port;

		this.applyConfig();

		if (this.username == null) {
			try {
				this.username = (String) System.getProperties().get("user.name");
			} catch (final SecurityException e) {
				// ignore e
			}
		}

		if (this.username == null) {
			throw new JSchException("username is not given.");
		}
	}

	public void connect() throws JSchException {
		this.connect(this.timeout);
	}

	public void connect(final int connectTimeout) throws JSchException {
		if (this.isConnected) {
			throw new JSchException("session is already connected");
		}

		this.io = new IO();
		if (random == null) {
			try {
				final Class<?> c = Class.forName(this.getConfig("random"));
				random = (Random) c.newInstance();
			} catch (final Exception e) {
				throw new JSchException(e.toString(), e);
			}
		}
		Packet.setRandom(random);

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"Connecting to " + this.host + " port " + this.port);
		}

		try {
			int i, j;

			if (this.proxy == null) {
				InputStream in;
				OutputStream out;
				if (this.socket_factory == null) {
					this.socket = Util.createSocket(this.host, this.port, connectTimeout);
					in = this.socket.getInputStream();
					out = this.socket.getOutputStream();
				} else {
					this.socket = this.socket_factory.createSocket(this.host, this.port);
					in = this.socket_factory.getInputStream(this.socket);
					out = this.socket_factory.getOutputStream(this.socket);
				}
				// if(timeout>0){ socket.setSoTimeout(timeout); }
				this.socket.setTcpNoDelay(true);
				this.io.setInputStream(in);
				this.io.setOutputStream(out);
			} else {
				synchronized (this.proxy) {
					this.proxy.connect(this.socket_factory, this.host, this.port, connectTimeout);
					this.io.setInputStream(this.proxy.getInputStream());
					this.io.setOutputStream(this.proxy.getOutputStream());
					this.socket = this.proxy.getSocket();
				}
			}

			if (connectTimeout > 0 && this.socket != null) {
				this.socket.setSoTimeout(connectTimeout);
			}

			this.isConnected = true;

			if (JSch.getLogger().isEnabled(Logger.INFO)) {
				JSch.getLogger().log(Logger.INFO,
						"Connection established");
			}

			this.jsch.addSession(this);

			{
				// Some Cisco devices will miss to read '\n' if it is sent separately.
				final byte[] foo = new byte[this.V_C.length + 1];
				System.arraycopy(this.V_C, 0, foo, 0, this.V_C.length);
				foo[foo.length - 1] = (byte) '\n';
				this.io.put(foo, 0, foo.length);
			}

			while (true) {
				i = 0;
				j = 0;
				while (i < this.buf.buffer.length) {
					j = this.io.getByte();
					if (j < 0) {
						break;
					}
					this.buf.buffer[i] = (byte) j;
					i++;
					if (j == 10) {
						break;
					}
				}
				if (j < 0) {
					throw new JSchException("connection is closed by foreign host");
				}

				if (this.buf.buffer[i - 1] == 10) { // 0x0a
					i--;
					if (i > 0 && this.buf.buffer[i - 1] == 13) { // 0x0d
						i--;
					}
				}

				if (i <= 3 ||
						i != this.buf.buffer.length &&
								(this.buf.buffer[0] != 'S' || this.buf.buffer[1] != 'S' ||
										this.buf.buffer[2] != 'H' || this.buf.buffer[3] != '-')) {
					// It must not start with 'SSH-'
					// System.err.println(new String(buf.buffer, 0, i);
					continue;
				}

				if (i == this.buf.buffer.length ||
						i < 7 || // SSH-1.99 or SSH-2.0
						this.buf.buffer[4] == '1' && this.buf.buffer[6] != '9' // SSH-1.5
				) {
					throw new JSchException("invalid server's version string");
				}
				break;
			}

			this.V_S = new byte[i];
			System.arraycopy(this.buf.buffer, 0, this.V_S, 0, i);
			// System.err.println("V_S: ("+i+") ["+new String(V_S)+"]");

			if (JSch.getLogger().isEnabled(Logger.INFO)) {
				JSch.getLogger().log(Logger.INFO,
						"Remote version string: " + Util.byte2str(this.V_S));
				JSch.getLogger().log(Logger.INFO,
						"Local version string: " + Util.byte2str(this.V_C));
			}

			this.send_kexinit();

			this.buf = this.read(this.buf);
			if (this.buf.getCommand() != SSH_MSG_KEXINIT) {
				this.in_kex = false;
				throw new JSchException("invalid protocol: " + this.buf.getCommand());
			}

			if (JSch.getLogger().isEnabled(Logger.INFO)) {
				JSch.getLogger().log(Logger.INFO,
						"SSH_MSG_KEXINIT received");
			}

			final KeyExchange kex = this.receive_kexinit(this.buf);

			while (true) {
				this.buf = this.read(this.buf);
				if (kex.getState() == this.buf.getCommand()) {
					this.kex_start_time = System.currentTimeMillis();
					final boolean result = kex.next(this.buf);
					if (!result) {
						// System.err.println("verify: "+result);
						this.in_kex = false;
						throw new JSchException("verify: " + result);
					}
				} else {
					this.in_kex = false;
					throw new JSchException("invalid protocol(kex): " + this.buf.getCommand());
				}
				if (kex.getState() == KeyExchange.STATE_END) {
					break;
				}
			}

			try {
				final long tmp = System.currentTimeMillis();
				this.in_prompt = true;
				this.checkHost(this.host, this.port, kex);
				this.in_prompt = false;
				this.kex_start_time += System.currentTimeMillis() - tmp;
			} catch (final JSchException ee) {
				this.in_kex = false;
				this.in_prompt = false;
				throw ee;
			}

			this.send_newkeys();

			// receive SSH_MSG_NEWKEYS(21)
			this.buf = this.read(this.buf);
			// System.err.println("read: 21 ? "+buf.getCommand());
			if (this.buf.getCommand() == SSH_MSG_NEWKEYS) {

				if (JSch.getLogger().isEnabled(Logger.INFO)) {
					JSch.getLogger().log(Logger.INFO,
							"SSH_MSG_NEWKEYS received");
				}

				this.receive_newkeys(this.buf, kex);
			} else {
				this.in_kex = false;
				throw new JSchException("invalid protocol(newkyes): " + this.buf.getCommand());
			}

			try {
				final String s = this.getConfig("MaxAuthTries");
				if (s != null) {
					this.max_auth_tries = Integer.parseInt(s);
				}
			} catch (final NumberFormatException e) {
				throw new JSchException("MaxAuthTries: " + this.getConfig("MaxAuthTries"), e);
			}

			boolean auth = false;
			boolean auth_cancel = false;

			UserAuth ua = null;
			try {
				final Class<?> c = Class.forName(this.getConfig("userauth.none"));
				ua = (UserAuth) c.newInstance();
			} catch (final Exception e) {
				throw new JSchException(e.toString(), e);
			}

			auth = ua.start(this);

			final String cmethods = this.getConfig("PreferredAuthentications");

			final String[] cmethoda = Util.split(cmethods, ",");

			String smethods = null;
			if (!auth) {
				smethods = ((UserAuthNone) ua).getMethods();
				if (smethods != null) {
					smethods = smethods.toLowerCase();
				} else {
					// methods: publickey,password,keyboard-interactive
					// smethods="publickey,password,keyboard-interactive";
					smethods = cmethods;
				}
			}

			String[] smethoda = Util.split(smethods, ",");

			int methodi = 0;

			loop: while (true) {

				while (!auth &&
						cmethoda != null && methodi < cmethoda.length) {

					final String method = cmethoda[methodi++];
					boolean acceptable = false;
					for (final String element : smethoda) {
						if (element.equals(method)) {
							acceptable = true;
							break;
						}
					}
					if (!acceptable) {
						continue;
					}

					// System.err.println(" method: "+method);

					if (JSch.getLogger().isEnabled(Logger.INFO)) {
						String str = "Authentications that can continue: ";
						for (int k = methodi - 1; k < cmethoda.length; k++) {
							str += cmethoda[k];
							if (k + 1 < cmethoda.length) {
								str += ",";
							}
						}
						JSch.getLogger().log(Logger.INFO,
								str);
						JSch.getLogger().log(Logger.INFO,
								"Next authentication method: " + method);
					}

					ua = null;
					try {
						Class<?> c = null;
						if (this.getConfig("userauth." + method) != null) {
							c = Class.forName(this.getConfig("userauth." + method));
							ua = (UserAuth) c.newInstance();
						}
					} catch (final Exception e) {
						if (JSch.getLogger().isEnabled(Logger.WARN)) {
							JSch.getLogger().log(Logger.WARN,
									"failed to load " + method + " method");
						}
					}

					if (ua != null) {
						auth_cancel = false;
						try {
							auth = ua.start(this);
							if (auth &&
									JSch.getLogger().isEnabled(Logger.INFO)) {
								JSch.getLogger().log(Logger.INFO,
										"Authentication succeeded (" + method + ").");
							}
						} catch (final JSchAuthCancelException ee) {
							auth_cancel = true;
						} catch (final JSchPartialAuthException ee) {
							final String tmp = smethods;
							smethods = ee.getMethods();
							smethoda = Util.split(smethods, ",");
							if (!tmp.equals(smethods)) {
								methodi = 0;
							}
							// System.err.println("PartialAuth: "+methods);
							auth_cancel = false;
							continue loop;
						} catch (final RuntimeException ee) {
							throw ee;
						} catch (final JSchException ee) {
							throw ee;
						} catch (final Exception ee) {
							// System.err.println("ee: "+ee); // SSH_MSG_DISCONNECT: 2 Too many authentication failures
							if (JSch.getLogger().isEnabled(Logger.WARN)) {
								JSch.getLogger().log(Logger.WARN,
										"an exception during authentication\n" + ee.toString());
							}
							break loop;
						}
					}
				}
				break;
			}

			if (!auth) {
				if (this.auth_failures >= this.max_auth_tries) {
					if (JSch.getLogger().isEnabled(Logger.INFO)) {
						JSch.getLogger().log(Logger.INFO,
								"Login trials exceeds " + this.max_auth_tries);
					}
				}
				if (auth_cancel) {
					throw new JSchException("Auth cancel");
				}
				throw new JSchException("Auth fail");
			}

			if (this.socket != null && (connectTimeout > 0 || this.timeout > 0)) {
				this.socket.setSoTimeout(this.timeout);
			}

			this.isAuthed = true;

			synchronized (this.lock) {
				if (this.isConnected) {
					this.connectThread = new Thread(this);
					this.connectThread.setName("Connect thread " + this.host + " session");
					if (this.daemon_thread) {
						this.connectThread.setDaemon(this.daemon_thread);
					}
					this.connectThread.start();

					this.requestPortForwarding();
				} else {
					// The session has been already down and
					// we don't have to start new thread.
				}
			}
		} catch (final Exception e) {
			this.in_kex = false;
			try {
				if (this.isConnected) {
					final String message = e.toString();
					this.packet.reset();
					this.buf.checkFreeSize(1 + 4 * 3 + message.length() + 2 + buffer_margin);
					this.buf.putByte((byte) SSH_MSG_DISCONNECT);
					this.buf.putInt(3);
					this.buf.putString(Util.str2byte(message));
					this.buf.putString(Util.str2byte("en"));
					this.write(this.packet);
				}
			} catch (final Exception ee) {}
			try {
				this.disconnect();
			} catch (final Exception ee) {}
			this.isConnected = false;
			// e.printStackTrace();
			if (e instanceof RuntimeException) {
				throw (RuntimeException) e;
			}
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			throw new JSchException("Session.connect: " + e);
		} finally {
			Util.bzero(this.password);
			this.password = null;
		}
	}

	private KeyExchange receive_kexinit(final Buffer buf) throws Exception {
		final int j = buf.getInt();
		if (j != buf.getLength()) { // packet was compressed and
			buf.getByte(); // j is the size of deflated packet.
			this.I_S = new byte[buf.index - 5];
		} else {
			this.I_S = new byte[j - 1 - buf.getByte()];
		}
		System.arraycopy(buf.buffer, buf.s, this.I_S, 0, this.I_S.length);

		if (!this.in_kex) { // We are in rekeying activated by the remote!
			this.send_kexinit();
		}

		this.guess = KeyExchange.guess(this.I_S, this.I_C);
		if (this.guess == null) {
			throw new JSchException("Algorithm negotiation fail");
		}

		if (!this.isAuthed &&
				(this.guess[KeyExchange.PROPOSAL_ENC_ALGS_CTOS].equals("none") ||
						this.guess[KeyExchange.PROPOSAL_ENC_ALGS_STOC].equals("none"))) {
			throw new JSchException("NONE Cipher should not be chosen before authentification is successed.");
		}

		KeyExchange kex = null;
		try {
			final Class<?> c = Class.forName(this.getConfig(this.guess[KeyExchange.PROPOSAL_KEX_ALGS]));
			kex = (KeyExchange) c.newInstance();
		} catch (final Exception e) {
			throw new JSchException(e.toString(), e);
		}

		kex.init(this, this.V_S, this.V_C, this.I_S, this.I_C);
		return kex;
	}

	private volatile boolean in_kex = false;
	private volatile boolean in_prompt = false;

	public void rekey() throws Exception {
		this.send_kexinit();
	}

	private void send_kexinit() throws Exception {
		if (this.in_kex) {
			return;
		}

		String cipherc2s = this.getConfig("cipher.c2s");
		String ciphers2c = this.getConfig("cipher.s2c");

		final String[] not_available_ciphers = this.checkCiphers(this.getConfig("CheckCiphers"));
		if (not_available_ciphers != null && not_available_ciphers.length > 0) {
			cipherc2s = Util.diffString(cipherc2s, not_available_ciphers);
			ciphers2c = Util.diffString(ciphers2c, not_available_ciphers);
			if (cipherc2s == null || ciphers2c == null) {
				throw new JSchException("There are not any available ciphers.");
			}
		}

		String kex = this.getConfig("kex");
		final String[] not_available_kexes = this.checkKexes(this.getConfig("CheckKexes"));
		if (not_available_kexes != null && not_available_kexes.length > 0) {
			kex = Util.diffString(kex, not_available_kexes);
			if (kex == null) {
				throw new JSchException("There are not any available kexes.");
			}
		}

		String server_host_key = this.getConfig("server_host_key");
		final String[] not_available_shks = Session.checkSignatures(this.getConfig("CheckSignatures"));
		if (not_available_shks != null && not_available_shks.length > 0) {
			server_host_key = Util.diffString(server_host_key, not_available_shks);
			if (server_host_key == null) {
				throw new JSchException("There are not any available sig algorithm.");
			}
		}

		this.in_kex = true;
		this.kex_start_time = System.currentTimeMillis();

		// byte SSH_MSG_KEXINIT(20)
		// byte[16] cookie (random bytes)
		// string kex_algorithms
		// string server_host_key_algorithms
		// string encryption_algorithms_client_to_server
		// string encryption_algorithms_server_to_client
		// string mac_algorithms_client_to_server
		// string mac_algorithms_server_to_client
		// string compression_algorithms_client_to_server
		// string compression_algorithms_server_to_client
		// string languages_client_to_server
		// string languages_server_to_client
		final Buffer buf = new Buffer(); // send_kexinit may be invoked
		final Packet packet = new Packet(buf); // by user thread.
		packet.reset();
		buf.putByte((byte) SSH_MSG_KEXINIT);
		synchronized (random) {
			random.fill(buf.buffer, buf.index, 16);
			buf.skip(16);
		}
		buf.putString(Util.str2byte(kex));
		buf.putString(Util.str2byte(server_host_key));
		buf.putString(Util.str2byte(cipherc2s));
		buf.putString(Util.str2byte(ciphers2c));
		buf.putString(Util.str2byte(this.getConfig("mac.c2s")));
		buf.putString(Util.str2byte(this.getConfig("mac.s2c")));
		buf.putString(Util.str2byte(this.getConfig("compression.c2s")));
		buf.putString(Util.str2byte(this.getConfig("compression.s2c")));
		buf.putString(Util.str2byte(this.getConfig("lang.c2s")));
		buf.putString(Util.str2byte(this.getConfig("lang.s2c")));
		buf.putByte((byte) 0);
		buf.putInt(0);

		buf.setOffSet(5);
		this.I_C = new byte[buf.getLength()];
		buf.getByte(this.I_C);

		this.write(packet);

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"SSH_MSG_KEXINIT sent");
		}
	}

	private void send_newkeys() throws Exception {
		// send SSH_MSG_NEWKEYS(21)
		this.packet.reset();
		this.buf.putByte((byte) SSH_MSG_NEWKEYS);
		this.write(this.packet);

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"SSH_MSG_NEWKEYS sent");
		}
	}

	private void checkHost(String chost, final int port, final KeyExchange kex) throws JSchException {
		final String shkc = this.getConfig("StrictHostKeyChecking");

		if (this.hostKeyAlias != null) {
			chost = this.hostKeyAlias;
		}

		// System.err.println("shkc: "+shkc);

		final byte[] K_S = kex.getHostKey();
		final String key_type = kex.getKeyType();
		final String key_fprint = kex.getFingerPrint();

		if (this.hostKeyAlias == null && port != 22) {
			chost = "[" + chost + "]:" + port;
		}

		final HostKeyRepository hkr = this.getHostKeyRepository();

		final String hkh = this.getConfig("HashKnownHosts");
		if (hkh.equals("yes") && hkr instanceof KnownHosts) {
			this.hostkey = ((KnownHosts) hkr).createHashedHostKey(chost, K_S);
		} else {
			this.hostkey = new HostKey(chost, K_S);
		}

		int i = 0;
		synchronized (hkr) {
			i = hkr.check(chost, K_S);
		}

		boolean insert = false;
		if ((shkc.equals("ask") || shkc.equals("yes")) &&
				i == HostKeyRepository.CHANGED) {
			String file = null;
			synchronized (hkr) {
				file = hkr.getKnownHostsRepositoryID();
			}
			if (file == null) {
				file = "known_hosts";
			}

			boolean b = false;

			if (this.userinfo != null) {
				final String message = "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\n" +
						"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\n" +
						"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\n" +
						"It is also possible that the " + key_type + " host key has just been changed.\n" +
						"The fingerprint for the " + key_type + " key sent by the remote host " + chost + " is\n" +
						key_fprint + ".\n" +
						"Please contact your system administrator.\n" +
						"Add correct host key in " + file + " to get rid of this message.";

				if (shkc.equals("ask")) {
					b = this.userinfo.promptYesNo(message +
							"\nDo you want to delete the old key and insert the new key?");
				} else { // shkc.equals("yes")
					this.userinfo.showMessage(message);
				}
			}

			if (!b) {
				throw new JSchException("HostKey has been changed: " + chost);
			}

			synchronized (hkr) {
				hkr.remove(chost,
						kex.getKeyAlgorithName(),
						null);
				insert = true;
			}
		}

		if ((shkc.equals("ask") || shkc.equals("yes")) &&
				i != HostKeyRepository.OK && !insert) {
			if (shkc.equals("yes")) {
				throw new JSchException("reject HostKey: " + this.host);
			}
			// System.err.println("finger-print: "+key_fprint);
			if (this.userinfo != null) {
				final boolean foo = this.userinfo.promptYesNo(
						"The authenticity of host '" + this.host + "' can't be established.\n" +
								key_type + " key fingerprint is " + key_fprint + ".\n" +
								"Are you sure you want to continue connecting?");
				if (!foo) {
					throw new JSchException("reject HostKey: " + this.host);
				}
				insert = true;
			} else {
				if (i == HostKeyRepository.NOT_INCLUDED) {
					throw new JSchException("UnknownHostKey: " + this.host + ". " + key_type + " key fingerprint is " + key_fprint);
				}
				throw new JSchException("HostKey has been changed: " + this.host);
			}
		}

		if (shkc.equals("no") &&
				HostKeyRepository.NOT_INCLUDED == i) {
			insert = true;
		}

		if (i == HostKeyRepository.OK) {
			final HostKey[] keys = hkr.getHostKey(chost, kex.getKeyAlgorithName());
			final String _key = Util.byte2str(Util.toBase64(K_S, 0, K_S.length));
			for (final HostKey key : keys) {
				if (keys[i].getKey().equals(_key) &&
						key.getMarker().equals("@revoked")) {
					if (this.userinfo != null) {
						this.userinfo.showMessage(
								"The " + key_type + " host key for " + this.host + " is marked as revoked.\n" +
										"This could mean that a stolen key is being used to " +
										"impersonate this host.");
					}
					if (JSch.getLogger().isEnabled(Logger.INFO)) {
						JSch.getLogger().log(Logger.INFO,
								"Host '" + this.host + "' has provided revoked key.");
					}
					throw new JSchException("revoked HostKey: " + this.host);
				}
			}
		}

		if (i == HostKeyRepository.OK &&
				JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"Host '" + this.host + "' is known and matches the " + key_type + " host key");
		}

		if (insert &&
				JSch.getLogger().isEnabled(Logger.WARN)) {
			JSch.getLogger().log(Logger.WARN,
					"Permanently added '" + this.host + "' (" + key_type + ") to the list of known hosts.");
		}

		if (insert) {
			synchronized (hkr) {
				hkr.add(this.hostkey, this.userinfo);
			}
		}
	}

	// public void start(){ (new Thread(this)).start(); }

	public Channel openChannel(final String type) throws JSchException {
		if (!this.isConnected) {
			throw new JSchException("session is down");
		}
		try {
			final Channel channel = Channel.getChannel(type);
			this.addChannel(channel);
			channel.init();
			if (channel instanceof ChannelSession) {
				this.applyConfigChannel((ChannelSession) channel);
			}
			return channel;
		} catch (final Exception e) {
			// e.printStackTrace();
		}
		return null;
	}

	// encode will bin invoked in write with synchronization.
	public void encode(final Packet packet) throws Exception {
		// System.err.println("encode: "+packet.buffer.getCommand());
		// System.err.println(" "+packet.buffer.index);
		// if(packet.buffer.getCommand()==96){
		// Thread.dumpStack();
		// }
		if (this.deflater != null) {
			this.compress_len[0] = packet.buffer.index;
			packet.buffer.buffer = this.deflater.compress(packet.buffer.buffer,
					5, this.compress_len);
			packet.buffer.index = this.compress_len[0];
		}
		if (this.c2scipher != null) {
			// packet.padding(c2scipher.getIVSize());
			packet.padding(this.c2scipher_size);
			final int pad = packet.buffer.buffer[4];
			synchronized (random) {
				random.fill(packet.buffer.buffer, packet.buffer.index - pad, pad);
			}
		} else {
			packet.padding(8);
		}

		if (this.c2smac != null) {
			this.c2smac.update(this.seqo);
			this.c2smac.update(packet.buffer.buffer, 0, packet.buffer.index);
			this.c2smac.doFinal(packet.buffer.buffer, packet.buffer.index);
		}
		if (this.c2scipher != null) {
			final byte[] buf = packet.buffer.buffer;
			this.c2scipher.update(buf, 0, packet.buffer.index, buf, 0);
		}
		if (this.c2smac != null) {
			packet.buffer.skip(this.c2smac.getBlockSize());
		}
	}

	int[] uncompress_len = new int[1];
	int[] compress_len = new int[1];

	private int s2ccipher_size = 8;
	private int c2scipher_size = 8;

	public Buffer read(final Buffer buf) throws Exception {
		int j = 0;
		while (true) {
			buf.reset();
			this.io.getByte(buf.buffer, buf.index, this.s2ccipher_size);
			buf.index += this.s2ccipher_size;
			if (this.s2ccipher != null) {
				this.s2ccipher.update(buf.buffer, 0, this.s2ccipher_size, buf.buffer, 0);
			}
			j = buf.buffer[0] << 24 & 0xff000000 |
					buf.buffer[1] << 16 & 0x00ff0000 |
					buf.buffer[2] << 8 & 0x0000ff00 |
					buf.buffer[3] & 0x000000ff;
			// RFC 4253 6.1. Maximum Packet Length
			if (j < 5 || j > PACKET_MAX_SIZE) {
				this.start_discard(buf, this.s2ccipher, this.s2cmac, j, PACKET_MAX_SIZE);
			}
			final int need = j + 4 - this.s2ccipher_size;
			// if(need<0){
			// throw new IOException("invalid data");
			// }
			if (buf.index + need > buf.buffer.length) {
				final byte[] foo = new byte[buf.index + need];
				System.arraycopy(buf.buffer, 0, foo, 0, buf.index);
				buf.buffer = foo;
			}

			if (need % this.s2ccipher_size != 0) {
				final String message = "Bad packet length " + need;
				if (JSch.getLogger().isEnabled(Logger.FATAL)) {
					JSch.getLogger().log(Logger.FATAL, message);
				}
				this.start_discard(buf, this.s2ccipher, this.s2cmac, j, PACKET_MAX_SIZE - this.s2ccipher_size);
			}

			if (need > 0) {
				this.io.getByte(buf.buffer, buf.index, need);
				buf.index += need;
				if (this.s2ccipher != null) {
					this.s2ccipher.update(buf.buffer, this.s2ccipher_size, need, buf.buffer, this.s2ccipher_size);
				}
			}

			if (this.s2cmac != null) {
				this.s2cmac.update(this.seqi);
				this.s2cmac.update(buf.buffer, 0, buf.index);

				this.s2cmac.doFinal(this.s2cmac_result1, 0);
				this.io.getByte(this.s2cmac_result2, 0, this.s2cmac_result2.length);
				if (!java.util.Arrays.equals(this.s2cmac_result1, this.s2cmac_result2)) {
					if (need > PACKET_MAX_SIZE) {
						throw new IOException("MAC Error");
					}
					this.start_discard(buf, this.s2ccipher, this.s2cmac, j, PACKET_MAX_SIZE - need);
					continue;
				}
			}

			this.seqi++;

			if (this.inflater != null) {
				// inflater.uncompress(buf);
				final int pad = buf.buffer[4];
				this.uncompress_len[0] = buf.index - 5 - pad;
				final byte[] foo = this.inflater.uncompress(buf.buffer, 5, this.uncompress_len);
				if (foo != null) {
					buf.buffer = foo;
					buf.index = 5 + this.uncompress_len[0];
				} else {
					System.err.println("fail in inflater");
					break;
				}
			}

			final int type = buf.getCommand() & 0xff;
			// System.err.println("read: "+type);
			if (type == SSH_MSG_DISCONNECT) {
				buf.rewind();
				buf.getInt();
				buf.getShort();
				final int reason_code = buf.getInt();
				final byte[] description = buf.getString();
				final byte[] language_tag = buf.getString();
				throw new JSchException("SSH_MSG_DISCONNECT: " +
						reason_code +
						" " + Util.byte2str(description) +
						" " + Util.byte2str(language_tag));
				// break;
			} else if (type == SSH_MSG_IGNORE) {} else if (type == SSH_MSG_UNIMPLEMENTED) {
				buf.rewind();
				buf.getInt();
				buf.getShort();
				final int reason_id = buf.getInt();
				if (JSch.getLogger().isEnabled(Logger.INFO)) {
					JSch.getLogger().log(Logger.INFO,
							"Received SSH_MSG_UNIMPLEMENTED for " + reason_id);
				}
			} else if (type == SSH_MSG_DEBUG) {
				buf.rewind();
				buf.getInt();
				buf.getShort();
				/*
				 * byte always_display=(byte)buf.getByte();
				 * byte[] message=buf.getString();
				 * byte[] language_tag=buf.getString();
				 * System.err.println("SSH_MSG_DEBUG:"+
				 * " "+Util.byte2str(message)+
				 * " "+Util.byte2str(language_tag));
				 */
			} else if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
				buf.rewind();
				buf.getInt();
				buf.getShort();
				final Channel c = Channel.getChannel(buf.getInt(), this);
				if (c == null) {} else {
					c.addRemoteWindowSize(buf.getUInt());
				}
			} else if (type == UserAuth.SSH_MSG_USERAUTH_SUCCESS) {
				this.isAuthed = true;
				if (this.inflater == null && this.deflater == null) {
					String method;
					method = this.guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
					this.initDeflater(method);
					method = this.guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
					this.initInflater(method);
				}
				break;
			} else {
				break;
			}
		}
		buf.rewind();
		return buf;
	}

	private void start_discard(final Buffer buf, final Cipher cipher, final MAC mac,
			final int packet_length, int discard) throws JSchException, IOException {
		MAC discard_mac = null;

		if (!cipher.isCBC()) {
			throw new JSchException("Packet corrupt");
		}

		if (packet_length != PACKET_MAX_SIZE && mac != null) {
			discard_mac = mac;
		}

		discard -= buf.index;

		while (discard > 0) {
			buf.reset();
			final int len = discard > buf.buffer.length ? buf.buffer.length : discard;
			this.io.getByte(buf.buffer, 0, len);
			if (discard_mac != null) {
				discard_mac.update(buf.buffer, 0, len);
			}
			discard -= len;
		}

		if (discard_mac != null) {
			discard_mac.doFinal(buf.buffer, 0);
		}

		throw new JSchException("Packet corrupt");
	}

	byte[] getSessionId() {
		return this.session_id;
	}

	private void receive_newkeys(final Buffer buf, final KeyExchange kex) throws Exception {
		this.updateKeys(kex);
		this.in_kex = false;
	}

	private void updateKeys(final KeyExchange kex) throws Exception {
		final byte[] K = kex.getK();
		final byte[] H = kex.getH();
		final HASH hash = kex.getHash();

		if (this.session_id == null) {
			this.session_id = new byte[H.length];
			System.arraycopy(H, 0, this.session_id, 0, H.length);
		}

		/*
		 * Initial IV client to server: HASH (K || H || "A" || session_id)
		 * Initial IV server to client: HASH (K || H || "B" || session_id)
		 * Encryption key client to server: HASH (K || H || "C" || session_id)
		 * Encryption key server to client: HASH (K || H || "D" || session_id)
		 * Integrity key client to server: HASH (K || H || "E" || session_id)
		 * Integrity key server to client: HASH (K || H || "F" || session_id)
		 */

		this.buf.reset();
		this.buf.putMPInt(K);
		this.buf.putByte(H);
		this.buf.putByte((byte) 0x41);
		this.buf.putByte(this.session_id);
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.IVc2s = hash.digest();

		final int j = this.buf.index - this.session_id.length - 1;

		this.buf.buffer[j]++;
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.IVs2c = hash.digest();

		this.buf.buffer[j]++;
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.Ec2s = hash.digest();

		this.buf.buffer[j]++;
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.Es2c = hash.digest();

		this.buf.buffer[j]++;
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.MACc2s = hash.digest();

		this.buf.buffer[j]++;
		hash.update(this.buf.buffer, 0, this.buf.index);
		this.MACs2c = hash.digest();

		try {
			Class<?> c;
			String method;

			method = this.guess[KeyExchange.PROPOSAL_ENC_ALGS_STOC];
			c = Class.forName(this.getConfig(method));
			this.s2ccipher = (Cipher) c.newInstance();
			while (this.s2ccipher.getBlockSize() > this.Es2c.length) {
				this.buf.reset();
				this.buf.putMPInt(K);
				this.buf.putByte(H);
				this.buf.putByte(this.Es2c);
				hash.update(this.buf.buffer, 0, this.buf.index);
				final byte[] foo = hash.digest();
				final byte[] bar = new byte[this.Es2c.length + foo.length];
				System.arraycopy(this.Es2c, 0, bar, 0, this.Es2c.length);
				System.arraycopy(foo, 0, bar, this.Es2c.length, foo.length);
				this.Es2c = bar;
			}
			this.s2ccipher.init(Cipher.DECRYPT_MODE, this.Es2c, this.IVs2c);
			this.s2ccipher_size = this.s2ccipher.getIVSize();

			method = this.guess[KeyExchange.PROPOSAL_MAC_ALGS_STOC];
			c = Class.forName(this.getConfig(method));
			this.s2cmac = (MAC) c.newInstance();
			this.MACs2c = Session.expandKey(this.buf, K, H, this.MACs2c, hash, this.s2cmac.getBlockSize());
			this.s2cmac.init(this.MACs2c);
			// mac_buf=new byte[s2cmac.getBlockSize()];
			this.s2cmac_result1 = new byte[this.s2cmac.getBlockSize()];
			this.s2cmac_result2 = new byte[this.s2cmac.getBlockSize()];

			method = this.guess[KeyExchange.PROPOSAL_ENC_ALGS_CTOS];
			c = Class.forName(this.getConfig(method));
			this.c2scipher = (Cipher) c.newInstance();
			while (this.c2scipher.getBlockSize() > this.Ec2s.length) {
				this.buf.reset();
				this.buf.putMPInt(K);
				this.buf.putByte(H);
				this.buf.putByte(this.Ec2s);
				hash.update(this.buf.buffer, 0, this.buf.index);
				final byte[] foo = hash.digest();
				final byte[] bar = new byte[this.Ec2s.length + foo.length];
				System.arraycopy(this.Ec2s, 0, bar, 0, this.Ec2s.length);
				System.arraycopy(foo, 0, bar, this.Ec2s.length, foo.length);
				this.Ec2s = bar;
			}
			this.c2scipher.init(Cipher.ENCRYPT_MODE, this.Ec2s, this.IVc2s);
			this.c2scipher_size = this.c2scipher.getIVSize();

			method = this.guess[KeyExchange.PROPOSAL_MAC_ALGS_CTOS];
			c = Class.forName(this.getConfig(method));
			this.c2smac = (MAC) c.newInstance();
			this.MACc2s = Session.expandKey(this.buf, K, H, this.MACc2s, hash, this.c2smac.getBlockSize());
			this.c2smac.init(this.MACc2s);

			method = this.guess[KeyExchange.PROPOSAL_COMP_ALGS_CTOS];
			this.initDeflater(method);

			method = this.guess[KeyExchange.PROPOSAL_COMP_ALGS_STOC];
			this.initInflater(method);
		} catch (final Exception e) {
			if (e instanceof JSchException) {
				throw e;
			}
			throw new JSchException(e.toString(), e);
			// System.err.println("updatekeys: "+e);
		}
	}

	/*
	 * RFC 4253 7.2. Output from Key Exchange
	 * If the key length needed is longer than the output of the HASH, the
	 * key is extended by computing HASH of the concatenation of K and H and
	 * the entire key so far, and appending the resulting bytes (as many as
	 * HASH generates) to the key. This process is repeated until enough
	 * key material is available; the key is taken from the beginning of
	 * this value. In other words:
	 * K1 = HASH(K || H || X || session_id) (X is e.g., "A")
	 * K2 = HASH(K || H || K1)
	 * K3 = HASH(K || H || K1 || K2)
	 * ...
	 * key = K1 || K2 || K3 || ...
	 */
	private static byte[] expandKey(final Buffer buf, final byte[] K, final byte[] H, final byte[] key,
			final HASH hash, final int required_length) throws Exception {
		byte[] result = key;
		final int size = hash.getBlockSize();
		while (result.length < required_length) {
			buf.reset();
			buf.putMPInt(K);
			buf.putByte(H);
			buf.putByte(result);
			hash.update(buf.buffer, 0, buf.index);
			final byte[] tmp = new byte[result.length + size];
			System.arraycopy(result, 0, tmp, 0, result.length);
			System.arraycopy(hash.digest(), 0, tmp, result.length, size);
			Util.bzero(result);
			result = tmp;
		}
		return result;
	}

	/* public */ /* synchronized */ void write(final Packet packet, final Channel c, int length) throws Exception {
		final long t = this.getTimeout();
		while (true) {
			if (this.in_kex) {
				if (t > 0L && System.currentTimeMillis() - this.kex_start_time > t) {
					throw new JSchException("timeout in waiting for rekeying process.");
				}
				try {
					Thread.sleep(10);
				} catch (final java.lang.InterruptedException e) {}
				continue;
			}
			synchronized (c) {

				if (c.rwsize < length) {
					try {
						c.notifyme++;
						c.wait(100);
					} catch (final java.lang.InterruptedException e) {} finally {
						c.notifyme--;
					}
				}

				if (this.in_kex) {
					continue;
				}

				if (c.rwsize >= length) {
					c.rwsize -= length;
					break;
				}

			}
			if (c.close || !c.isConnected()) {
				throw new IOException("channel is broken");
			}

			boolean sendit = false;
			int s = 0;
			byte command = 0;
			int recipient = -1;
			synchronized (c) {
				if (c.rwsize > 0) {
					long len = c.rwsize;
					if (len > length) {
						len = length;
					}
					if (len != length) {
						s = packet.shift((int) len,
								this.c2scipher != null ? this.c2scipher_size : 8,
								this.c2smac != null ? this.c2smac.getBlockSize() : 0);
					}
					command = packet.buffer.getCommand();
					recipient = c.getRecipient();
					length -= len;
					c.rwsize -= len;
					sendit = true;
				}
			}
			if (sendit) {
				this._write(packet);
				if (length == 0) {
					return;
				}
				packet.unshift(command, recipient, s, length);
			}

			synchronized (c) {
				if (this.in_kex) {
					continue;
				}
				if (c.rwsize >= length) {
					c.rwsize -= length;
					break;
				}

				// try{
				// System.out.println("1wait: "+c.rwsize);
				// c.notifyme++;
				// c.wait(100);
				// }
				// catch(java.lang.InterruptedException e){
				// }
				// finally{
				// c.notifyme--;
				// }
			}
		}
		this._write(packet);
	}

	public void write(final Packet packet) throws Exception {
		// System.err.println("in_kex="+in_kex+" "+(packet.buffer.getCommand()));
		final long t = this.getTimeout();
		while (this.in_kex) {
			if (t > 0L &&
					System.currentTimeMillis() - this.kex_start_time > t &&
					!this.in_prompt) {
				throw new JSchException("timeout in waiting for rekeying process.");
			}
			final byte command = packet.buffer.getCommand();
			// System.err.println("command: "+command);
			if (command == SSH_MSG_KEXINIT ||
					command == SSH_MSG_NEWKEYS ||
					command == SSH_MSG_KEXDH_INIT ||
					command == SSH_MSG_KEXDH_REPLY ||
					command == SSH_MSG_KEX_DH_GEX_GROUP ||
					command == SSH_MSG_KEX_DH_GEX_INIT ||
					command == SSH_MSG_KEX_DH_GEX_REPLY ||
					command == SSH_MSG_KEX_DH_GEX_REQUEST ||
					command == SSH_MSG_DISCONNECT) {
				break;
			}
			try {
				Thread.sleep(10);
			} catch (final java.lang.InterruptedException e) {}
		}
		this._write(packet);
	}

	private void _write(final Packet packet) throws Exception {
		synchronized (this.lock) {
			this.encode(packet);
			if (this.io != null) {
				this.io.put(packet);
				this.seqo++;
			}
		}
	}

	Runnable thread;

	@Override
	public void run() {
		this.thread = this;

		byte[] foo;
		Buffer buf = new Buffer();
		final Packet packet = new Packet(buf);
		int i = 0;
		Channel channel;
		final int[] start = new int[1];
		final int[] length = new int[1];
		KeyExchange kex = null;

		int stimeout = 0;
		try {
			while (this.isConnected &&
					this.thread != null) {
				try {
					buf = this.read(buf);
					stimeout = 0;
				} catch (final InterruptedIOException/* SocketTimeoutException */ ee) {
					if (!this.in_kex && stimeout < this.serverAliveCountMax) {
						this.sendKeepAliveMsg();
						stimeout++;
						continue;
					} else if (this.in_kex && stimeout < this.serverAliveCountMax) {
						stimeout++;
						continue;
					}
					throw ee;
				}

				final int msgType = buf.getCommand() & 0xff;

				if (kex != null && kex.getState() == msgType) {
					this.kex_start_time = System.currentTimeMillis();
					final boolean result = kex.next(buf);
					if (!result) {
						throw new JSchException("verify: " + result);
					}
					continue;
				}

				switch (msgType) {
					case SSH_MSG_KEXINIT:
						// System.err.println("KEXINIT");
						kex = this.receive_kexinit(buf);
						break;

					case SSH_MSG_NEWKEYS:
						// System.err.println("NEWKEYS");
						this.send_newkeys();
						this.receive_newkeys(buf, kex);
						kex = null;
						break;

					case SSH_MSG_CHANNEL_DATA:
						buf.getInt();
						buf.getByte();
						buf.getByte();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						foo = buf.getString(start, length);
						if (channel == null) {
							break;
						}

						if (length[0] == 0) {
							break;
						}

						try {
							channel.write(foo, start[0], length[0]);
						} catch (final Exception e) {
							// System.err.println(e);
							try {
								channel.disconnect();
							} catch (final Exception ee) {}
							break;
						}
						int len = length[0];
						channel.setLocalWindowSize(channel.lwsize - len);
						if (channel.lwsize < channel.lwsize_max / 2) {
							packet.reset();
							buf.putByte((byte) SSH_MSG_CHANNEL_WINDOW_ADJUST);
							buf.putInt(channel.getRecipient());
							buf.putInt(channel.lwsize_max - channel.lwsize);
							synchronized (channel) {
								if (!channel.close) {
									this.write(packet);
								}
							}
							channel.setLocalWindowSize(channel.lwsize_max);
						}
						break;

					case SSH_MSG_CHANNEL_EXTENDED_DATA:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						buf.getInt(); // data_type_code == 1
						foo = buf.getString(start, length);
						// System.err.println("stderr: "+new String(foo,start[0],length[0]));
						if (channel == null) {
							break;
						}

						if (length[0] == 0) {
							break;
						}

						channel.write_ext(foo, start[0], length[0]);

						len = length[0];
						channel.setLocalWindowSize(channel.lwsize - len);
						if (channel.lwsize < channel.lwsize_max / 2) {
							packet.reset();
							buf.putByte((byte) SSH_MSG_CHANNEL_WINDOW_ADJUST);
							buf.putInt(channel.getRecipient());
							buf.putInt(channel.lwsize_max - channel.lwsize);
							synchronized (channel) {
								if (!channel.close) {
									this.write(packet);
								}
							}
							channel.setLocalWindowSize(channel.lwsize_max);
						}
						break;

					case SSH_MSG_CHANNEL_WINDOW_ADJUST:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel == null) {
							break;
						}
						channel.addRemoteWindowSize(buf.getUInt());
						break;

					case SSH_MSG_CHANNEL_EOF:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel != null) {
							// channel.eof_remote=true;
							// channel.eof();
							channel.eof_remote();
						}
						/*
						 * packet.reset();
						 * buf.putByte((byte)SSH_MSG_CHANNEL_EOF);
						 * buf.putInt(channel.getRecipient());
						 * write(packet);
						 */
						break;
					case SSH_MSG_CHANNEL_CLOSE:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel != null) {
							// channel.close();
							channel.disconnect();
						}
						/*
						 * if(Channel.pool.size()==0){
						 * thread=null;
						 * }
						 */
						break;
					case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						final int r = buf.getInt();
						final long rws = buf.getUInt();
						final int rps = buf.getInt();
						if (channel != null) {
							channel.setRemoteWindowSize(rws);
							channel.setRemotePacketSize(rps);
							channel.open_confirmation = true;
							channel.setRecipient(r);
						}
						break;
					case SSH_MSG_CHANNEL_OPEN_FAILURE:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel != null) {
							final int reason_code = buf.getInt();
							// foo=buf.getString(); // additional textual information
							// foo=buf.getString(); // language tag
							channel.setExitStatus(reason_code);
							channel.close = true;
							channel.eof_remote = true;
							channel.setRecipient(0);
						}
						break;
					case SSH_MSG_CHANNEL_REQUEST:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						foo = buf.getString();
						boolean reply = buf.getByte() != 0;
						channel = Channel.getChannel(i, this);
						if (channel != null) {
							byte reply_type = (byte) SSH_MSG_CHANNEL_FAILURE;
							if (Util.byte2str(foo).equals("exit-status")) {
								i = buf.getInt(); // exit-status
								channel.setExitStatus(i);
								reply_type = (byte) SSH_MSG_CHANNEL_SUCCESS;
							}
							if (reply) {
								packet.reset();
								buf.putByte(reply_type);
								buf.putInt(channel.getRecipient());
								this.write(packet);
							}
						} else {}
						break;
					case SSH_MSG_CHANNEL_OPEN:
						buf.getInt();
						buf.getShort();
						foo = buf.getString();
						final String ctyp = Util.byte2str(foo);
						if (!"forwarded-tcpip".equals(ctyp) &&
								!("x11".equals(ctyp) && this.x11_forwarding) &&
								!("auth-agent@openssh.com".equals(ctyp) && this.agent_forwarding)) {
							// System.err.println("Session.run: CHANNEL OPEN "+ctyp);
							// throw new IOException("Session.run: CHANNEL OPEN "+ctyp);
							packet.reset();
							buf.putByte((byte) SSH_MSG_CHANNEL_OPEN_FAILURE);
							buf.putInt(buf.getInt());
							buf.putInt(Channel.SSH_OPEN_ADMINISTRATIVELY_PROHIBITED);
							buf.putString(Util.empty);
							buf.putString(Util.empty);
							this.write(packet);
						} else {
							channel = Channel.getChannel(ctyp);
							this.addChannel(channel);
							channel.getData(buf);
							channel.init();

							final Thread tmp = new Thread(channel);
							tmp.setName("Channel " + ctyp + " " + this.host);
							if (this.daemon_thread) {
								tmp.setDaemon(this.daemon_thread);
							}
							tmp.start();
						}
						break;
					case SSH_MSG_CHANNEL_SUCCESS:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel == null) {
							break;
						}
						channel.reply = 1;
						break;
					case SSH_MSG_CHANNEL_FAILURE:
						buf.getInt();
						buf.getShort();
						i = buf.getInt();
						channel = Channel.getChannel(i, this);
						if (channel == null) {
							break;
						}
						channel.reply = 0;
						break;
					case SSH_MSG_GLOBAL_REQUEST:
						buf.getInt();
						buf.getShort();
						foo = buf.getString(); // request name
						reply = buf.getByte() != 0;
						if (reply) {
							packet.reset();
							buf.putByte((byte) SSH_MSG_REQUEST_FAILURE);
							this.write(packet);
						}
						break;
					case SSH_MSG_REQUEST_FAILURE:
					case SSH_MSG_REQUEST_SUCCESS:
						final Thread t = this.grr.getThread();
						if (t != null) {
							this.grr.setReply(msgType == SSH_MSG_REQUEST_SUCCESS ? 1 : 0);
							if (msgType == SSH_MSG_REQUEST_SUCCESS && this.grr.getPort() == 0) {
								buf.getInt();
								buf.getShort();
								this.grr.setPort(buf.getInt());
							}
							t.interrupt();
						}
						break;
					default:
						// System.err.println("Session.run: unsupported type "+msgType);
						throw new IOException("Unknown SSH message type " + msgType);
				}
			}
		} catch (final Exception e) {
			this.in_kex = false;
			if (JSch.getLogger().isEnabled(Logger.INFO)) {
				JSch.getLogger().log(Logger.INFO,
						"Caught an exception, leaving main loop due to " + e.getMessage());
			}
			// System.err.println("# Session.run");
			// e.printStackTrace();
		}
		try {
			this.disconnect();
		} catch (final NullPointerException e) {
			// System.err.println("@1");
			// e.printStackTrace();
		} catch (final Exception e) {
			// System.err.println("@2");
			// e.printStackTrace();
		}
		this.isConnected = false;
	}

	public void disconnect() {
		if (!this.isConnected) {
			return;
		}
		// System.err.println(this+": disconnect");
		// Thread.dumpStack();
		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"Disconnecting from " + this.host + " port " + this.port);
		}
		/*
		 * for(int i=0; i<Channel.pool.size(); i++){
		 * try{
		 * Channel c=((Channel)(Channel.pool.elementAt(i)));
		 * if(c.session==this) c.eof();
		 * }
		 * catch(Exception e){
		 * }
		 * }
		 */

		Channel.disconnect(this);

		this.isConnected = false;

		PortWatcher.delPort(this);
		ChannelForwardedTCPIP.delPort(this);
		ChannelX11.removeFakedCookie(this);

		synchronized (this.lock) {
			if (this.connectThread != null) {
				Thread.yield();
				this.connectThread.interrupt();
				this.connectThread = null;
			}
		}
		this.thread = null;
		try {
			if (this.io != null) {
				if (this.io.in != null) {
					this.io.in.close();
				}
				if (this.io.out != null) {
					this.io.out.close();
				}
				if (this.io.out_ext != null) {
					this.io.out_ext.close();
				}
			}
			if (this.proxy == null) {
				if (this.socket != null) {
					this.socket.close();
				}
			} else {
				synchronized (this.proxy) {
					this.proxy.close();
				}
				this.proxy = null;
			}
		} catch (final Exception e) {
			// e.printStackTrace();
		}
		this.io = null;
		this.socket = null;
		// synchronized(jsch.pool){
		// jsch.pool.removeElement(this);
		// }

		this.jsch.removeSession(this);

		// System.gc();
	}

	/**
	 * Registers the local port forwarding for loop-back interface.
	 * If <code>lport</code> is <code>0</code>, the tcp port will be allocated.
	 *
	 * @param lport local port for local port forwarding
	 * @param host host address for local port forwarding
	 * @param rport remote port number for local port forwarding
	 * @return an allocated local TCP port number
	 * @see #setPortForwardingL(String bind_address, int lport, String host, int rport, ServerSocketFactory ssf, int connectTimeout)
	 */
	public int setPortForwardingL(final int lport, final String host, final int rport) throws JSchException {
		return this.setPortForwardingL("127.0.0.1", lport, host, rport);
	}

	/**
	 * Registers the local port forwarding. If <code>bind_address</code> is an empty string
	 * or '*', the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or
	 * <code>null</code>, the listening port will be bound for local use only.
	 * If <code>lport</code> is <code>0</code>, the tcp port will be allocated.
	 *
	 * @param bind_address bind address for local port forwarding
	 * @param lport local port for local port forwarding
	 * @param host host address for local port forwarding
	 * @param rport remote port number for local port forwarding
	 * @return an allocated local TCP port number
	 * @see #setPortForwardingL(String bind_address, int lport, String host, int rport, ServerSocketFactory ssf, int connectTimeout)
	 */
	public int setPortForwardingL(final String bind_address, final int lport, final String host, final int rport) throws JSchException {
		return this.setPortForwardingL(bind_address, lport, host, rport, null);
	}

	/**
	 * Registers the local port forwarding.
	 * If <code>bind_address</code> is an empty string or <code>"*"</code>,
	 * the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or
	 * <code>null</code>, the listening port will be bound for local use only.
	 * If <code>lport</code> is <code>0</code>, the tcp port will be allocated.
	 *
	 * @param bind_address bind address for local port forwarding
	 * @param lport local port for local port forwarding
	 * @param host host address for local port forwarding
	 * @param rport remote port number for local port forwarding
	 * @param ssf socket factory
	 * @return an allocated local TCP port number
	 * @see #setPortForwardingL(String bind_address, int lport, String host, int rport, ServerSocketFactory ssf, int connectTimeout)
	 */
	public int setPortForwardingL(final String bind_address, final int lport, final String host, final int rport, final ServerSocketFactory ssf) throws JSchException {
		return this.setPortForwardingL(bind_address, lport, host, rport, ssf, 0);
	}

	/**
	 * Registers the local port forwarding.
	 * If <code>bind_address</code> is an empty string
	 * or <code>"*"</code>, the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or
	 * <code>null</code>, the listening port will be bound for local use only.
	 * If <code>lport</code> is <code>0</code>, the tcp port will be allocated.
	 *
	 * @param bind_address bind address for local port forwarding
	 * @param lport local port for local port forwarding
	 * @param host host address for local port forwarding
	 * @param rport remote port number for local port forwarding
	 * @param ssf socket factory
	 * @param connectTimeout timeout for establishing port connection
	 * @return an allocated local TCP port number
	 */
	public int setPortForwardingL(final String bind_address, final int lport, final String host, final int rport, final ServerSocketFactory ssf, final int connectTimeout) throws JSchException {
		final PortWatcher pw = PortWatcher.addPort(this, bind_address, lport, host, rport, ssf);
		pw.setConnectTimeout(connectTimeout);
		final Thread tmp = new Thread(pw);
		tmp.setName("PortWatcher Thread for " + host);
		if (this.daemon_thread) {
			tmp.setDaemon(this.daemon_thread);
		}
		tmp.start();
		return pw.lport;
	}

	/**
	 * Cancels the local port forwarding assigned
	 * at local TCP port <code>lport</code> on loopback interface.
	 *
	 * @param lport local TCP port
	 */
	public void delPortForwardingL(final int lport) throws JSchException {
		this.delPortForwardingL("127.0.0.1", lport);
	}

	/**
	 * Cancels the local port forwarding assigned
	 * at local TCP port <code>lport</code> on <code>bind_address</code> interface.
	 *
	 * @param bind_address bind_address of network interfaces
	 * @param lport local TCP port
	 */
	public void delPortForwardingL(final String bind_address, final int lport) throws JSchException {
		PortWatcher.delPort(this, bind_address, lport);
	}

	/**
	 * Lists the registered local port forwarding.
	 *
	 * @return a list of "lport:host:hostport"
	 */
	public String[] getPortForwardingL() throws JSchException {
		return PortWatcher.getPortForwarding(this);
	}

	/**
	 * Registers the remote port forwarding for the loopback interface
	 * of the remote.
	 *
	 * @param rport remote port
	 * @param host host address
	 * @param lport local port
	 * @see #setPortForwardingR(String bind_address, int rport, String host, int lport, SocketFactory sf)
	 */
	public void setPortForwardingR(final int rport, final String host, final int lport) throws JSchException {
		this.setPortForwardingR(null, rport, host, lport, (SocketFactory) null);
	}

	/**
	 * Registers the remote port forwarding.
	 * If <code>bind_address</code> is an empty string or <code>"*"</code>,
	 * the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or is not given,
	 * the listening port will be bound for local use only.
	 * Note that if <code>GatewayPorts</code> is <code>"no"</code> on the
	 * remote, <code>"localhost"</code> is always used as a bind_address.
	 *
	 * @param bind_address bind address
	 * @param rport remote port
	 * @param host host address
	 * @param lport local port
	 * @see #setPortForwardingR(String bind_address, int rport, String host, int lport, SocketFactory sf)
	 */
	public void setPortForwardingR(final String bind_address, final int rport, final String host, final int lport) throws JSchException {
		this.setPortForwardingR(bind_address, rport, host, lport, (SocketFactory) null);
	}

	/**
	 * Registers the remote port forwarding for the loopback interface
	 * of the remote.
	 *
	 * @param rport remote port
	 * @param host host address
	 * @param lport local port
	 * @param sf socket factory
	 * @see #setPortForwardingR(String bind_address, int rport, String host, int lport, SocketFactory sf)
	 */
	public void setPortForwardingR(final int rport, final String host, final int lport, final SocketFactory sf) throws JSchException {
		this.setPortForwardingR(null, rport, host, lport, sf);
	}

	// TODO: This method should return the integer value as the assigned port.
	/**
	 * Registers the remote port forwarding.
	 * If <code>bind_address</code> is an empty string or <code>"*"</code>,
	 * the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or is not given,
	 * the listening port will be bound for local use only.
	 * Note that if <code>GatewayPorts</code> is <code>"no"</code> on the
	 * remote, <code>"localhost"</code> is always used as a bind_address.
	 * If <code>rport</code> is <code>0</code>, the TCP port will be allocated on the remote.
	 *
	 * @param bind_address bind address
	 * @param rport remote port
	 * @param host host address
	 * @param lport local port
	 * @param sf socket factory
	 */
	public void setPortForwardingR(final String bind_address, final int rport, final String host, final int lport, final SocketFactory sf) throws JSchException {
		final int allocated = this._setPortForwardingR(bind_address, rport);
		ChannelForwardedTCPIP.addPort(this, bind_address,
				rport, allocated, host, lport, sf);
	}

	/**
	 * Registers the remote port forwarding for the loopback interface
	 * of the remote.
	 * The TCP connection to <code>rport</code> on the remote will be
	 * forwarded to an instance of the class <code>daemon</code>.
	 * The class specified by <code>daemon</code> must implement
	 * <code>ForwardedTCPIPDaemon</code>.
	 *
	 * @param rport remote port
	 * @param daemon class name, which implements "ForwardedTCPIPDaemon"
	 * @see #setPortForwardingR(String bind_address, int rport, String daemon, Object[] arg)
	 */
	public void setPortForwardingR(final int rport, final String daemon) throws JSchException {
		this.setPortForwardingR(null, rport, daemon, null);
	}

	/**
	 * Registers the remote port forwarding for the loopback interface
	 * of the remote.
	 * The TCP connection to <code>rport</code> on the remote will be
	 * forwarded to an instance of the class <code>daemon</code> with
	 * the argument <code>arg</code>.
	 * The class specified by <code>daemon</code> must implement <code>ForwardedTCPIPDaemon</code>.
	 *
	 * @param rport remote port
	 * @param daemon class name, which implements "ForwardedTCPIPDaemon"
	 * @param arg arguments for "daemon"
	 * @see #setPortForwardingR(String bind_address, int rport, String daemon, Object[] arg)
	 */
	public void setPortForwardingR(final int rport, final String daemon, final Object[] arg) throws JSchException {
		this.setPortForwardingR(null, rport, daemon, arg);
	}

	/**
	 * Registers the remote port forwarding.
	 * If <code>bind_address</code> is an empty string
	 * or <code>"*"</code>, the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or is not given,
	 * the listening port will be bound for local use only.
	 * Note that if <code>GatewayPorts</code> is <code>"no"</code> on the
	 * remote, <code>"localhost"</code> is always used as a bind_address.
	 * The TCP connection to <code>rport</code> on the remote will be
	 * forwarded to an instance of the class <code>daemon</code> with the
	 * argument <code>arg</code>.
	 * The class specified by <code>daemon</code> must implement <code>ForwardedTCPIPDaemon</code>.
	 *
	 * @param bind_address bind address
	 * @param rport remote port
	 * @param daemon class name, which implements "ForwardedTCPIPDaemon"
	 * @param arg arguments for "daemon"
	 * @see #setPortForwardingR(String bind_address, int rport, String daemon, Object[] arg)
	 */
	public void setPortForwardingR(final String bind_address, final int rport, final String daemon, final Object[] arg) throws JSchException {
		final int allocated = this._setPortForwardingR(bind_address, rport);
		ChannelForwardedTCPIP.addPort(this, bind_address,
				rport, allocated, daemon, arg);
	}

	/**
	 * Lists the registered remote port forwarding.
	 *
	 * @return a list of "rport:host:hostport"
	 */
	public String[] getPortForwardingR() throws JSchException {
		return ChannelForwardedTCPIP.getPortForwarding(this);
	}

	private class Forwarding {

		String bind_address = null;
		int port = -1;
		String host = null;
		int hostport = -1;
	}

	/**
	 * The given argument may be "[bind_address:]port:host:hostport" or
	 * "[bind_address:]port host:hostport", which is from LocalForward command of
	 * ~/.ssh/config .
	 */
	private Forwarding parseForwarding(String conf) throws JSchException {
		final String[] tmp = conf.split(" ");
		if (tmp.length > 1) { // "[bind_address:]port host:hostport"
			final Vector<String> foo = new Vector<String>();
			for (final String element : tmp) {
				if (element.length() == 0) {
					continue;
				}
				foo.addElement(element.trim());
			}
			final StringBuffer sb = new StringBuffer(); // join
			for (int i = 0; i < foo.size(); i++) {
				sb.append(foo.elementAt(i));
				if (i + 1 < foo.size()) {
					sb.append(":");
				}
			}
			conf = sb.toString();
		}

		final String org = conf;
		final Forwarding f = new Forwarding();
		try {
			if (conf.lastIndexOf(":") == -1) {
				throw new JSchException("parseForwarding: " + org);
			}
			f.hostport = Integer.parseInt(conf.substring(conf.lastIndexOf(":") + 1));
			conf = conf.substring(0, conf.lastIndexOf(":"));
			if (conf.lastIndexOf(":") == -1) {
				throw new JSchException("parseForwarding: " + org);
			}
			f.host = conf.substring(conf.lastIndexOf(":") + 1);
			conf = conf.substring(0, conf.lastIndexOf(":"));
			if (conf.lastIndexOf(":") != -1) {
				f.port = Integer.parseInt(conf.substring(conf.lastIndexOf(":") + 1));
				conf = conf.substring(0, conf.lastIndexOf(":"));
				if (conf.length() == 0 || conf.equals("*")) {
					conf = "0.0.0.0";
				}
				if (conf.equals("localhost")) {
					conf = "127.0.0.1";
				}
				f.bind_address = conf;
			} else {
				f.port = Integer.parseInt(conf);
				f.bind_address = "127.0.0.1";
			}
		} catch (final NumberFormatException e) {
			throw new JSchException("parseForwarding: " + e.toString());
		}
		return f;
	}

	/**
	 * Registers the local port forwarding. The argument should be
	 * in the format like "[bind_address:]port:host:hostport".
	 * If <code>bind_address</code> is an empty string or <code>"*"</code>,
	 * the port should be available from all interfaces.
	 * If <code>bind_address</code> is <code>"localhost"</code> or is not given,
	 * the listening port will be bound for local use only.
	 *
	 * @param conf configuration of local port forwarding
	 * @return an assigned port number
	 * @see #setPortForwardingL(String bind_address, int lport, String host, int rport)
	 */
	public int setPortForwardingL(final String conf) throws JSchException {
		final Forwarding f = this.parseForwarding(conf);
		return this.setPortForwardingL(f.bind_address, f.port, f.host, f.hostport);
	}

	/**
	 * Registers the remote port forwarding. The argument should be
	 * in the format like "[bind_address:]port:host:hostport". If the
	 * bind_address is not given, the default is to only bind to loopback
	 * addresses. If the bind_address is <code>"*"</code> or an empty string,
	 * then the forwarding is requested to listen on all interfaces.
	 * Note that if <code>GatewayPorts</code> is <code>"no"</code> on the remote,
	 * <code>"localhost"</code> is always used for bind_address.
	 * If the specified remote is <code>"0"</code>,
	 * the TCP port will be allocated on the remote.
	 *
	 * @param conf configuration of remote port forwarding
	 * @return an allocated TCP port on the remote.
	 * @see #setPortForwardingR(String bind_address, int rport, String host, int rport)
	 */
	public int setPortForwardingR(final String conf) throws JSchException {
		final Forwarding f = this.parseForwarding(conf);
		final int allocated = this._setPortForwardingR(f.bind_address, f.port);
		ChannelForwardedTCPIP.addPort(this, f.bind_address,
				f.port, allocated, f.host, f.hostport, null);
		return allocated;
	}

	/**
	 * Instantiates an instance of stream-forwarder to <code>host</code>:<code>port</code>.
	 * Set I/O stream to the given channel, and then invoke Channel#connect() method.
	 *
	 * @param host remote host, which the given stream will be plugged to.
	 * @param port remote port, which the given stream will be plugged to.
	 */
	public Channel getStreamForwarder(final String host, final int port) throws JSchException {
		final ChannelDirectTCPIP channel = new ChannelDirectTCPIP();
		channel.init();
		this.addChannel(channel);
		channel.setHost(host);
		channel.setPort(port);
		return channel;
	}

	private class GlobalRequestReply {

		private Thread thread = null;
		private int reply = -1;
		private int port = 0;

		void setThread(final Thread thread) {
			this.thread = thread;
			this.reply = -1;
		}

		Thread getThread() {
			return this.thread;
		}

		void setReply(final int reply) {
			this.reply = reply;
		}

		int getReply() {
			return this.reply;
		}

		int getPort() {
			return this.port;
		}

		void setPort(final int port) {
			this.port = port;
		}
	}

	private final GlobalRequestReply grr = new GlobalRequestReply();

	private int _setPortForwardingR(final String bind_address, int rport) throws JSchException {
		synchronized (this.grr) {
			final Buffer buf = new Buffer(100); // ??
			final Packet packet = new Packet(buf);

			final String address_to_bind = ChannelForwardedTCPIP.normalize(bind_address);

			this.grr.setThread(Thread.currentThread());
			this.grr.setPort(rport);

			try {
				// byte SSH_MSG_GLOBAL_REQUEST 80
				// string "tcpip-forward"
				// boolean want_reply
				// string address_to_bind
				// uint32 port number to bind
				packet.reset();
				buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
				buf.putString(Util.str2byte("tcpip-forward"));
				buf.putByte((byte) 1);
				buf.putString(Util.str2byte(address_to_bind));
				buf.putInt(rport);
				this.write(packet);
			} catch (final Exception e) {
				this.grr.setThread(null);
				if (e instanceof Throwable) {
					throw new JSchException(e.toString(), e);
				}
				throw new JSchException(e.toString());
			}

			int count = 0;
			int reply = this.grr.getReply();
			while (count < 10 && reply == -1) {
				try {
					Thread.sleep(1000);
				} catch (final Exception e) {}
				count++;
				reply = this.grr.getReply();
			}
			this.grr.setThread(null);
			if (reply != 1) {
				throw new JSchException("remote port forwarding failed for listen port " + rport);
			}
			rport = this.grr.getPort();
		}
		return rport;
	}

	/**
	 * Cancels the remote port forwarding assigned at remote TCP port <code>rport</code>.
	 *
	 * @param rport remote TCP port
	 */
	public void delPortForwardingR(final int rport) throws JSchException {
		this.delPortForwardingR(null, rport);
	}

	/**
	 * Cancels the remote port forwarding assigned at
	 * remote TCP port <code>rport</code> bound on the interface at
	 * <code>bind_address</code>.
	 *
	 * @param bind_address bind address of the interface on the remote
	 * @param rport remote TCP port
	 */
	public void delPortForwardingR(final String bind_address, final int rport) throws JSchException {
		ChannelForwardedTCPIP.delPort(this, bind_address, rport);
	}

	private void initDeflater(final String method) throws JSchException {
		if (method.equals("none")) {
			this.deflater = null;
			return;
		}
		final String foo = this.getConfig(method);
		if (foo != null) {
			if (method.equals("zlib") ||
					this.isAuthed && method.equals("zlib@openssh.com")) {
				try {
					final Class<?> c = Class.forName(foo);
					this.deflater = (Compression) c.newInstance();
					int level = 6;
					try {
						level = Integer.parseInt(this.getConfig("compression_level"));
					} catch (final Exception ee) {}
					this.deflater.init(Compression.DEFLATER, level);
				} catch (final NoClassDefFoundError ee) {
					throw new JSchException(ee.toString(), ee);
				} catch (final Exception ee) {
					throw new JSchException(ee.toString(), ee);
					// System.err.println(foo+" isn't accessible.");
				}
			}
		}
	}

	private void initInflater(final String method) throws JSchException {
		if (method.equals("none")) {
			this.inflater = null;
			return;
		}
		final String foo = this.getConfig(method);
		if (foo != null) {
			if (method.equals("zlib") ||
					this.isAuthed && method.equals("zlib@openssh.com")) {
				try {
					final Class<?> c = Class.forName(foo);
					this.inflater = (Compression) c.newInstance();
					this.inflater.init(Compression.INFLATER, 0);
				} catch (final Exception ee) {
					throw new JSchException(ee.toString(), ee);
					// System.err.println(foo+" isn't accessible.");
				}
			}
		}
	}

	void addChannel(final Channel channel) {
		channel.setSession(this);
	}

	public void setProxy(final Proxy proxy) {
		this.proxy = proxy;
	}

	public void setHost(final String host) {
		this.host = host;
	}

	public void setPort(final int port) {
		this.port = port;
	}

	void setUserName(final String username) {
		this.username = username;
	}

	public void setUserInfo(final UserInfo userinfo) {
		this.userinfo = userinfo;
	}

	public UserInfo getUserInfo() {
		return this.userinfo;
	}

	public void setInputStream(final InputStream in) {
		this.in = in;
	}

	public void setOutputStream(final OutputStream out) {
		this.out = out;
	}

	public void setX11Host(final String host) {
		ChannelX11.setHost(host);
	}

	public void setX11Port(final int port) {
		ChannelX11.setPort(port);
	}

	public void setX11Cookie(final String cookie) {
		ChannelX11.setCookie(cookie);
	}

	public void setPassword(final String password) {
		if (password != null) {
			this.password = Util.str2byte(password);
		}
	}

	public void setPassword(final byte[] password) {
		if (password != null) {
			this.password = new byte[password.length];
			System.arraycopy(password, 0, this.password, 0, password.length);
		}
	}

	public void setConfig(final java.util.Properties newconf) {
		this.setConfig((java.util.Hashtable) newconf);
	}

	public void setConfig(final java.util.Hashtable<String, String> newconf) {
		synchronized (this.lock) {
			if (this.config == null) {
				this.config = new java.util.Hashtable<String, String>();
			}
			for (final java.util.Enumeration<String> e = newconf.keys(); e.hasMoreElements();) {
				final String key = e.nextElement();
				this.config.put(key, newconf.get(key));
			}
		}
	}

	public void setConfig(final String key, final String value) {
		synchronized (this.lock) {
			if (this.config == null) {
				this.config = new java.util.Hashtable<String, String>();
			}
			this.config.put(key, value);
		}
	}

	public String getConfig(final String key) {
		Object foo = null;
		if (this.config != null) {
			foo = this.config.get(key);
			if (foo instanceof String) {
				return (String) foo;
			}
		}
		foo = JSch.getConfig(key);
		if (foo instanceof String) {
			return (String) foo;
		}
		return null;
	}

	public void setSocketFactory(final SocketFactory sfactory) {
		this.socket_factory = sfactory;
	}

	public boolean isConnected() {
		return this.isConnected;
	}

	public int getTimeout() {
		return this.timeout;
	}

	public void setTimeout(final int timeout) throws JSchException {
		if (this.socket == null) {
			if (timeout < 0) {
				throw new JSchException("invalid timeout value");
			}
			this.timeout = timeout;
			return;
		}
		try {
			this.socket.setSoTimeout(timeout);
			this.timeout = timeout;
		} catch (final Exception e) {
			if (e instanceof Throwable) {
				throw new JSchException(e.toString(), e);
			}
			throw new JSchException(e.toString());
		}
	}

	public String getServerVersion() {
		return Util.byte2str(this.V_S);
	}

	public String getClientVersion() {
		return Util.byte2str(this.V_C);
	}

	public void setClientVersion(final String cv) {
		this.V_C = Util.str2byte(cv);
	}

	public void sendIgnore() throws Exception {
		final Buffer buf = new Buffer();
		final Packet packet = new Packet(buf);
		packet.reset();
		buf.putByte((byte) SSH_MSG_IGNORE);
		this.write(packet);
	}

	private static final byte[] keepalivemsg = Util.str2byte("keepalive@jcraft.com");

	public void sendKeepAliveMsg() throws Exception {
		final Buffer buf = new Buffer();
		final Packet packet = new Packet(buf);
		packet.reset();
		buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
		buf.putString(keepalivemsg);
		buf.putByte((byte) 1);
		this.write(packet);
	}

	private static final byte[] nomoresessions = Util.str2byte("no-more-sessions@openssh.com");

	public void noMoreSessionChannels() throws Exception {
		final Buffer buf = new Buffer();
		final Packet packet = new Packet(buf);
		packet.reset();
		buf.putByte((byte) SSH_MSG_GLOBAL_REQUEST);
		buf.putString(nomoresessions);
		buf.putByte((byte) 0);
		this.write(packet);
	}

	private HostKey hostkey = null;

	public HostKey getHostKey() {
		return this.hostkey;
	}

	public String getHost() {
		return this.host;
	}

	public String getUserName() {
		return this.username;
	}

	public int getPort() {
		return this.port;
	}

	public void setHostKeyAlias(final String hostKeyAlias) {
		this.hostKeyAlias = hostKeyAlias;
	}

	public String getHostKeyAlias() {
		return this.hostKeyAlias;
	}

	/**
	 * Sets the interval to send a keep-alive message. If zero is
	 * specified, any keep-alive message must not be sent. The default interval
	 * is zero.
	 *
	 * @param interval the specified interval, in milliseconds.
	 * @see #getServerAliveInterval()
	 */
	public void setServerAliveInterval(final int interval) throws JSchException {
		this.setTimeout(interval);
		this.serverAliveInterval = interval;
	}

	/**
	 * Returns setting for the interval to send a keep-alive message.
	 *
	 * @see #setServerAliveInterval(int)
	 */
	public int getServerAliveInterval() {
		return this.serverAliveInterval;
	}

	/**
	 * Sets the number of keep-alive messages which may be sent without
	 * receiving any messages back from the server. If this threshold is
	 * reached while keep-alive messages are being sent, the connection will
	 * be disconnected. The default value is one.
	 *
	 * @param count the specified count
	 * @see #getServerAliveCountMax()
	 */
	public void setServerAliveCountMax(final int count) {
		this.serverAliveCountMax = count;
	}

	/**
	 * Returns setting for the threshold to send keep-alive messages.
	 *
	 * @see #setServerAliveCountMax(int)
	 */
	public int getServerAliveCountMax() {
		return this.serverAliveCountMax;
	}

	public void setDaemonThread(final boolean enable) {
		this.daemon_thread = enable;
	}

	private String[] checkCiphers(final String ciphers) {
		if (ciphers == null || ciphers.length() == 0) {
			return null;
		}

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"CheckCiphers: " + ciphers);
		}

		final String cipherc2s = this.getConfig("cipher.c2s");
		final String ciphers2c = this.getConfig("cipher.s2c");

		final Vector<String> result = new Vector<String>();
		final String[] _ciphers = Util.split(ciphers, ",");
		for (final String cipher : _ciphers) {
			if (ciphers2c.indexOf(cipher) == -1 && cipherc2s.indexOf(cipher) == -1) {
				continue;
			}
			if (!checkCipher(this.getConfig(cipher))) {
				result.addElement(cipher);
			}
		}
		if (result.size() == 0) {
			return null;
		}
		final String[] foo = new String[result.size()];
		System.arraycopy(result.toArray(), 0, foo, 0, result.size());

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			for (final String element : foo) {
				JSch.getLogger().log(Logger.INFO,
						element + " is not available.");
			}
		}

		return foo;
	}

	static boolean checkCipher(final String cipher) {
		try {
			final Class<?> c = Class.forName(cipher);
			final Cipher _c = (Cipher) c.newInstance();
			_c.init(Cipher.ENCRYPT_MODE,
					new byte[_c.getBlockSize()],
					new byte[_c.getIVSize()]);
			return true;
		} catch (final Exception e) {
			return false;
		}
	}

	private String[] checkKexes(final String kexes) {
		if (kexes == null || kexes.length() == 0) {
			return null;
		}

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"CheckKexes: " + kexes);
		}

		final java.util.Vector<String> result = new java.util.Vector<String>();
		final String[] _kexes = Util.split(kexes, ",");
		for (final String _kexe : _kexes) {
			if (!checkKex(this, this.getConfig(_kexe))) {
				result.addElement(_kexe);
			}
		}
		if (result.size() == 0) {
			return null;
		}
		final String[] foo = new String[result.size()];
		System.arraycopy(result.toArray(), 0, foo, 0, result.size());

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			for (final String element : foo) {
				JSch.getLogger().log(Logger.INFO,
						element + " is not available.");
			}
		}

		return foo;
	}

	static boolean checkKex(final Session s, final String kex) {
		try {
			final Class<?> c = Class.forName(kex);
			final KeyExchange _c = (KeyExchange) c.newInstance();
			_c.init(s, null, null, null, null);
			return true;
		} catch (final Exception e) {
			return false;
		}
	}

	private static String[] checkSignatures(final String sigs) {
		if (sigs == null || sigs.length() == 0) {
			return null;
		}

		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			JSch.getLogger().log(Logger.INFO,
					"CheckSignatures: " + sigs);
		}

		final java.util.Vector<String> result = new java.util.Vector<String>();
		final String[] _sigs = Util.split(sigs, ",");
		for (final String _sig : _sigs) {
			try {
				final Class c = Class.forName(JSch.getConfig(_sig));
				final Signature sig = (Signature) c.newInstance();
				sig.init();
			} catch (final Exception e) {
				result.addElement(_sig);
			}
		}
		if (result.size() == 0) {
			return null;
		}
		final String[] foo = new String[result.size()];
		System.arraycopy(result.toArray(), 0, foo, 0, result.size());
		if (JSch.getLogger().isEnabled(Logger.INFO)) {
			for (final String element : foo) {
				JSch.getLogger().log(Logger.INFO,
						element + " is not available.");
			}
		}
		return foo;
	}

	/**
	 * Sets the identityRepository, which will be referred
	 * in the public key authentication. The default value is <code>null</code>.
	 *
	 * @param identityRepository
	 * @see #getIdentityRepository()
	 */
	public void setIdentityRepository(final IdentityRepository identityRepository) {
		this.identityRepository = identityRepository;
	}

	/**
	 * Gets the identityRepository.
	 * If this.identityRepository is <code>null</code>,
	 * JSch#getIdentityRepository() will be invoked.
	 *
	 * @see JSch#getIdentityRepository()
	 */
	IdentityRepository getIdentityRepository() {
		if (this.identityRepository == null) {
			return this.jsch.getIdentityRepository();
		}
		return this.identityRepository;
	}

	/**
	 * Sets the hostkeyRepository, which will be referred in checking host keys.
	 *
	 * @param hostkeyRepository
	 * @see #getHostKeyRepository()
	 */
	public void setHostKeyRepository(final HostKeyRepository hostkeyRepository) {
		this.hostkeyRepository = hostkeyRepository;
	}

	/**
	 * Gets the hostkeyRepository.
	 * If this.hostkeyRepository is <code>null</code>,
	 * JSch#getHostKeyRepository() will be invoked.
	 *
	 * @see JSch#getHostKeyRepository()
	 */
	public HostKeyRepository getHostKeyRepository() {
		if (this.hostkeyRepository == null) {
			return this.jsch.getHostKeyRepository();
		}
		return this.hostkeyRepository;
	}

	/*
	 * // setProxyCommand("ssh -l user2 host2 -o 'ProxyCommand ssh user1@host1 nc host2 22' nc %h %p")
	 * public void setProxyCommand(String command){
	 * setProxy(new ProxyCommand(command));
	 * }
	 *
	 * class ProxyCommand implements Proxy {
	 * String command;
	 * Process p = null;
	 * InputStream in = null;
	 * OutputStream out = null;
	 * ProxyCommand(String command){
	 * this.command = command;
	 * }
	 * public void connect(SocketFactory socket_factory, String host, int port, int timeout) throws Exception {
	 * String _command = command.replace("%h", host);
	 * _command = _command.replace("%p", new Integer(port).toString());
	 * p = Runtime.getRuntime().exec(_command);
	 * in = p.getInputStream();
	 * out = p.getOutputStream();
	 * }
	 * public Socket getSocket() { return null; }
	 * public InputStream getInputStream() { return in; }
	 * public OutputStream getOutputStream() { return out; }
	 * public void close() {
	 * try{
	 * if(p!=null){
	 * p.getErrorStream().close();
	 * p.getOutputStream().close();
	 * p.getInputStream().close();
	 * p.destroy();
	 * p=null;
	 * }
	 * }
	 * catch(IOException e){
	 * }
	 * }
	 * }
	 */

	private void applyConfig() throws JSchException {
		final ConfigRepository configRepository = this.jsch.getConfigRepository();
		if (configRepository == null) {
			return;
		}

		final ConfigRepository.Config config = configRepository.getConfig(this.org_host);

		String value = null;

		if (this.username == null) {
			value = config.getUser();
			if (value != null) {
				this.username = value;
			}
		}

		value = config.getHostname();
		if (value != null) {
			this.host = value;
		}

		final int port = config.getPort();
		if (port != -1) {
			this.port = port;
		}

		this.checkConfig(config, "kex");
		this.checkConfig(config, "server_host_key");

		this.checkConfig(config, "cipher.c2s");
		this.checkConfig(config, "cipher.s2c");
		this.checkConfig(config, "mac.c2s");
		this.checkConfig(config, "mac.s2c");
		this.checkConfig(config, "compression.c2s");
		this.checkConfig(config, "compression.s2c");
		this.checkConfig(config, "compression_level");

		this.checkConfig(config, "StrictHostKeyChecking");
		this.checkConfig(config, "HashKnownHosts");
		this.checkConfig(config, "PreferredAuthentications");
		this.checkConfig(config, "MaxAuthTries");
		this.checkConfig(config, "ClearAllForwardings");

		value = config.getValue("HostKeyAlias");
		if (value != null) {
			this.setHostKeyAlias(value);
		}

		value = config.getValue("UserKnownHostsFile");
		if (value != null) {
			final KnownHosts kh = new KnownHosts(this.jsch);
			kh.setKnownHosts(value);
			this.setHostKeyRepository(kh);
		}

		final String[] values = config.getValues("IdentityFile");
		if (values != null) {
			String[] global = configRepository.getConfig("").getValues("IdentityFile");
			if (global != null) {
				for (final String element : global) {
					this.jsch.addIdentity(element);
				}
			} else {
				global = new String[0];
			}
			if (values.length - global.length > 0) {
				final IdentityRepository.Wrapper ir = new IdentityRepository.Wrapper(this.jsch.getIdentityRepository(), true);
				for (final String value2 : values) {
					String ifile = value2;
					for (final String element : global) {
						if (!ifile.equals(element)) {
							continue;
						}
						ifile = null;
						break;
					}
					if (ifile == null) {
						continue;
					}
					final Identity identity = IdentityFile.newInstance(ifile, null, this.jsch);
					ir.add(identity);
				}
				this.setIdentityRepository(ir);
			}
		}

		value = config.getValue("ServerAliveInterval");
		if (value != null) {
			try {
				this.setServerAliveInterval(Integer.parseInt(value));
			} catch (final NumberFormatException e) {}
		}

		value = config.getValue("ConnectTimeout");
		if (value != null) {
			try {
				this.setTimeout(Integer.parseInt(value));
			} catch (final NumberFormatException e) {}
		}

		value = config.getValue("MaxAuthTries");
		if (value != null) {
			this.setConfig("MaxAuthTries", value);
		}

		value = config.getValue("ClearAllForwardings");
		if (value != null) {
			this.setConfig("ClearAllForwardings", value);
		}

	}

	private void applyConfigChannel(final ChannelSession channel) throws JSchException {
		final ConfigRepository configRepository = this.jsch.getConfigRepository();
		if (configRepository == null) {
			return;
		}

		final ConfigRepository.Config config = configRepository.getConfig(this.org_host);

		String value = null;

		value = config.getValue("ForwardAgent");
		if (value != null) {
			channel.setAgentForwarding(value.equals("yes"));
		}

		value = config.getValue("RequestTTY");
		if (value != null) {
			channel.setPty(value.equals("yes"));
		}
	}

	private void requestPortForwarding() throws JSchException {

		if (this.getConfig("ClearAllForwardings").equals("yes")) {
			return;
		}

		final ConfigRepository configRepository = this.jsch.getConfigRepository();
		if (configRepository == null) {
			return;
		}

		final ConfigRepository.Config config = configRepository.getConfig(this.org_host);

		String[] values = config.getValues("LocalForward");
		if (values != null) {
			for (final String value : values) {
				this.setPortForwardingL(value);
			}
		}

		values = config.getValues("RemoteForward");
		if (values != null) {
			for (final String value : values) {
				this.setPortForwardingR(value);
			}
		}
	}

	private void checkConfig(final ConfigRepository.Config config, final String key) {
		final String value = config.getValue(key);
		if (value != null) {
			this.setConfig(key, value);
		}
	}
}
