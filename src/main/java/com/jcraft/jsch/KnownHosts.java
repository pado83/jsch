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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class KnownHosts implements HostKeyRepository {

	private String known_hosts = null;
	private java.util.Vector<HostKey> pool = null;

	private MAC hmacsha1 = null;

	KnownHosts(final JSch jsch) {
		super();
		this.hmacsha1 = this.getHMACSHA1();
		this.pool = new java.util.Vector<HostKey>();
	}

	void setKnownHosts(final String filename) throws JSchException {
		try {
			this.known_hosts = filename;
			final FileInputStream fis = new FileInputStream(Util.checkTilde(filename));
			this.setKnownHosts(fis);
		} catch (final FileNotFoundException e) {
			// The non-existing file should be allowed.
		}
	}

	void setKnownHosts(final InputStream input) throws JSchException {
		this.pool.removeAllElements();
		final StringBuffer sb = new StringBuffer();
		byte i;
		int j;
		final boolean error = false;
		try {
			final InputStream fis = input;
			String host;
			String key = null;
			int type;
			byte[] buf = new byte[1024];
			int bufl = 0;
			loop: while (true) {
				bufl = 0;
				while (true) {
					j = fis.read();
					if (j == -1) {
						if (bufl == 0) {
							break loop;
						}
						break;
					}
					if (j == 0x0d) {
						continue;
					}
					if (j == 0x0a) {
						break;
					}
					if (buf.length <= bufl) {
						if (bufl > 1024 * 10) {
							break; // too long...
						}
						final byte[] newbuf = new byte[buf.length * 2];
						System.arraycopy(buf, 0, newbuf, 0, buf.length);
						buf = newbuf;
					}
					buf[bufl++] = (byte) j;
				}

				j = 0;
				while (j < bufl) {
					i = buf[j];
					if (i == ' ' || i == '\t') {
						j++;
						continue;
					}
					if (i == '#') {
						this.addInvalidLine(Util.byte2str(buf, 0, bufl));
						continue loop;
					}
					break;
				}
				if (j >= bufl) {
					this.addInvalidLine(Util.byte2str(buf, 0, bufl));
					continue loop;
				}

				sb.setLength(0);
				while (j < bufl) {
					i = buf[j++];
					if (i == 0x20 || i == '\t') {
						break;
					}
					sb.append((char) i);
				}
				host = sb.toString();
				if (j >= bufl || host.length() == 0) {
					this.addInvalidLine(Util.byte2str(buf, 0, bufl));
					continue loop;
				}

				while (j < bufl) {
					i = buf[j];
					if (i == ' ' || i == '\t') {
						j++;
						continue;
					}
					break;
				}

				String marker = "";
				if (host.charAt(0) == '@') {
					marker = host;

					sb.setLength(0);
					while (j < bufl) {
						i = buf[j++];
						if (i == 0x20 || i == '\t') {
							break;
						}
						sb.append((char) i);
					}
					host = sb.toString();
					if (j >= bufl || host.length() == 0) {
						this.addInvalidLine(Util.byte2str(buf, 0, bufl));
						continue loop;
					}

					while (j < bufl) {
						i = buf[j];
						if (i == ' ' || i == '\t') {
							j++;
							continue;
						}
						break;
					}
				}

				sb.setLength(0);
				type = -1;
				while (j < bufl) {
					i = buf[j++];
					if (i == 0x20 || i == '\t') {
						break;
					}
					sb.append((char) i);
				}
				final String tmp = sb.toString();
				if (HostKey.name2type(tmp) != HostKey.UNKNOWN) {
					type = HostKey.name2type(tmp);
				} else {
					j = bufl;
				}
				if (j >= bufl) {
					this.addInvalidLine(Util.byte2str(buf, 0, bufl));
					continue loop;
				}

				while (j < bufl) {
					i = buf[j];
					if (i == ' ' || i == '\t') {
						j++;
						continue;
					}
					break;
				}

				sb.setLength(0);
				while (j < bufl) {
					i = buf[j++];
					if (i == 0x0d) {
						continue;
					}
					if (i == 0x0a) {
						break;
					}
					if (i == 0x20 || i == '\t') {
						break;
					}
					sb.append((char) i);
				}
				key = sb.toString();
				if (key.length() == 0) {
					this.addInvalidLine(Util.byte2str(buf, 0, bufl));
					continue loop;
				}

				while (j < bufl) {
					i = buf[j];
					if (i == ' ' || i == '\t') {
						j++;
						continue;
					}
					break;
				}

				/**
				 * "man sshd" has following descriptions,
				 * Note that the lines in these files are typically hundreds
				 * of characters long, and you definitely don't want to type
				 * in the host keys by hand. Rather, generate them by a script,
				 * ssh-keyscan(1) or by taking /usr/local/etc/ssh_host_key.pub and
				 * adding the host names at the front.
				 * This means that a comment is allowed to appear at the end of each
				 * key entry.
				 */
				String comment = null;
				if (j < bufl) {
					sb.setLength(0);
					while (j < bufl) {
						i = buf[j++];
						if (i == 0x0d) {
							continue;
						}
						if (i == 0x0a) {
							break;
						}
						sb.append((char) i);
					}
					comment = sb.toString();
				}

				// System.err.println(host);
				// System.err.println("|"+key+"|");

				HostKey hk = null;
				hk = new HashedHostKey(marker, host, type,
						Util.fromBase64(Util.str2byte(key), 0,
								key.length()), comment);
				this.pool.addElement(hk);
			}
			if (error) {
				throw new JSchException("KnownHosts: invalid format");
			}
		} catch (final Exception e) {
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			if (e instanceof Throwable) {
				throw new JSchException(e.toString(), e);
			}
			throw new JSchException(e.toString());
		} finally {
			try {
				input.close();
			} catch (final IOException e) {
				throw new JSchException(e.toString(), e);
			}
		}
	}

	private void addInvalidLine(final String line) throws JSchException {
		final HostKey hk = new HostKey(line, HostKey.UNKNOWN, null);
		this.pool.addElement(hk);
	}

	String getKnownHostsFile() {
		return this.known_hosts;
	}

	@Override
	public String getKnownHostsRepositoryID() {
		return this.known_hosts;
	}

	@Override
	public int check(final String host, final byte[] key) {
		int result = NOT_INCLUDED;
		if (host == null) {
			return result;
		}

		HostKey hk = null;
		try {
			hk = new HostKey(host, HostKey.GUESS, key);
		} catch (final JSchException e) { // unsupported key
			return result;
		}

		synchronized (this.pool) {
			for (int i = 0; i < this.pool.size(); i++) {
				final HostKey _hk = this.pool.elementAt(i);
				if (_hk.isMatched(host) && _hk.type == hk.type) {
					if (Util.array_equals(_hk.key, key)) {
						return OK;
					}
					result = CHANGED;
				}
			}
		}

		if (result == NOT_INCLUDED &&
				host.startsWith("[") &&
				host.indexOf("]:") > 1) {
			return this.check(host.substring(1, host.indexOf("]:")), key);
		}

		return result;
	}

	@Override
	public void add(final HostKey hostkey, final UserInfo userinfo) {
		final int type = hostkey.type;
		final String host = hostkey.getHost();
		HostKey hk = null;
		synchronized (this.pool) {
			for (int i = 0; i < this.pool.size(); i++) {
				hk = this.pool.elementAt(i);
				if (hk.isMatched(host) && hk.type == type) {
					/*
					 * if(Util.array_equals(hk.key, key)){ return; }
					 * if(hk.host.equals(host)){
					 * hk.key=key;
					 * return;
					 * }
					 * else{
					 * hk.host=deleteSubString(hk.host, host);
					 * break;
					 * }
					 */
				}
			}
		}

		hk = hostkey;

		this.pool.addElement(hk);

		final String bar = this.getKnownHostsRepositoryID();
		if (bar != null) {
			boolean foo = true;
			File goo = new File(Util.checkTilde(bar));
			if (!goo.exists()) {
				foo = false;
				if (userinfo != null) {
					foo = userinfo.promptYesNo(bar + " does not exist.\n" +
							"Are you sure you want to create it?");
					goo = goo.getParentFile();
					if (foo && goo != null && !goo.exists()) {
						foo = userinfo.promptYesNo("The parent directory " + goo + " does not exist.\n" +
								"Are you sure you want to create it?");
						if (foo) {
							if (!goo.mkdirs()) {
								userinfo.showMessage(goo + " has not been created.");
								foo = false;
							} else {
								userinfo.showMessage(goo + " has been succesfully created.\nPlease check its access permission.");
							}
						}
					}
					if (goo == null) {
						foo = false;
					}
				}
			}
			if (foo) {
				try {
					this.sync(bar);
				} catch (final Exception e) {
					System.err.println("sync known_hosts: " + e);
				}
			}
		}
	}

	@Override
	public HostKey[] getHostKey() {
		return this.getHostKey(null, (String) null);
	}

	@Override
	public HostKey[] getHostKey(final String host, final String type) {
		synchronized (this.pool) {
			final java.util.ArrayList<HostKey> v = new java.util.ArrayList<HostKey>();
			for (int i = 0; i < this.pool.size(); i++) {
				final HostKey hk = this.pool.elementAt(i);
				if (hk.type == HostKey.UNKNOWN) {
					continue;
				}
				if (host == null ||
						hk.isMatched(host) &&
								(type == null || hk.getType().equals(type))) {
					v.add(hk);
				}
			}
			HostKey[] foo = new HostKey[v.size()];
			for (int i = 0; i < v.size(); i++) {
				foo[i] = v.get(i);
			}
			if (host != null && host.startsWith("[") && host.indexOf("]:") > 1) {
				final HostKey[] tmp = this.getHostKey(host.substring(1, host.indexOf("]:")), type);
				if (tmp.length > 0) {
					final HostKey[] bar = new HostKey[foo.length + tmp.length];
					System.arraycopy(foo, 0, bar, 0, foo.length);
					System.arraycopy(tmp, 0, bar, foo.length, tmp.length);
					foo = bar;
				}
			}
			return foo;
		}
	}

	@Override
	public void remove(final String host, final String type) {
		this.remove(host, type, null);
	}

	@Override
	public void remove(final String host, final String type, final byte[] key) {
		boolean sync = false;
		synchronized (this.pool) {
			for (int i = 0; i < this.pool.size(); i++) {
				final HostKey hk = this.pool.elementAt(i);
				if (host == null ||
						hk.isMatched(host) &&
								(type == null || hk.getType().equals(type) &&
										(key == null || Util.array_equals(key, hk.key)))) {
					final String hosts = hk.getHost();
					if (hosts.equals(host) ||
							hk instanceof HashedHostKey &&
									((HashedHostKey) hk).isHashed()) {
						this.pool.removeElement(hk);
					} else {
						hk.host = KnownHosts.deleteSubString(hosts, host);
					}
					sync = true;
				}
			}
		}
		if (sync) {
			try {
				this.sync();
			} catch (final Exception e) {}
		}
	}

	protected void sync() throws IOException {
		if (this.known_hosts != null) {
			this.sync(this.known_hosts);
		}
	}

	protected synchronized void sync(final String foo) throws IOException {
		if (foo == null) {
			return;
		}
		final FileOutputStream fos = new FileOutputStream(Util.checkTilde(foo));
		this.dump(fos);
		fos.close();
	}

	private static final byte[] space = { (byte) 0x20 };
	private static final byte[] cr = Util.str2byte("\n");

	void dump(final OutputStream out) throws IOException {
		try {
			HostKey hk;
			synchronized (this.pool) {
				for (int i = 0; i < this.pool.size(); i++) {
					hk = this.pool.elementAt(i);
					// hk.dump(out);
					final String marker = hk.getMarker();
					final String host = hk.getHost();
					final String type = hk.getType();
					final String comment = hk.getComment();
					if (type.equals("UNKNOWN")) {
						out.write(Util.str2byte(host));
						out.write(cr);
						continue;
					}
					if (marker.length() != 0) {
						out.write(Util.str2byte(marker));
						out.write(space);
					}
					out.write(Util.str2byte(host));
					out.write(space);
					out.write(Util.str2byte(type));
					out.write(space);
					out.write(Util.str2byte(hk.getKey()));
					if (comment != null) {
						out.write(space);
						out.write(Util.str2byte(comment));
					}
					out.write(cr);
				}
			}
		} catch (final Exception e) {
			System.err.println(e);
		}
	}

	private static String deleteSubString(final String hosts, final String host) {
		int i = 0;
		final int hostlen = host.length();
		final int hostslen = hosts.length();
		int j;
		while (i < hostslen) {
			j = hosts.indexOf(',', i);
			if (j == -1) {
				break;
			}
			if (!host.equals(hosts.substring(i, j))) {
				i = j + 1;
				continue;
			}
			return hosts.substring(0, i) + hosts.substring(j + 1);
		}
		if (hosts.endsWith(host) && hostslen - i == hostlen) {
			return hosts.substring(0, hostlen == hostslen ? 0 : hostslen - hostlen - 1);
		}
		return hosts;
	}

	private MAC getHMACSHA1() {
		if (this.hmacsha1 == null) {
			try {
				final Class<?> c = Class.forName(JSch.getConfig("hmac-sha1"));
				this.hmacsha1 = (MAC) c.newInstance();
			} catch (final Exception e) {
				System.err.println("hmacsha1: " + e);
			}
		}
		return this.hmacsha1;
	}

	HostKey createHashedHostKey(final String host, final byte[] key) throws JSchException {
		final HashedHostKey hhk = new HashedHostKey(host, key);
		hhk.hash();
		return hhk;
	}

	class HashedHostKey extends HostKey {

		private static final String HASH_MAGIC = "|1|";
		private static final String HASH_DELIM = "|";

		private boolean hashed = false;
		byte[] salt = null;
		byte[] hash = null;

		HashedHostKey(final String host, final byte[] key) throws JSchException {
			this(host, GUESS, key);
		}

		HashedHostKey(final String host, final int type, final byte[] key) throws JSchException {
			this("", host, type, key, null);
		}

		HashedHostKey(final String marker, final String host, final int type, final byte[] key, final String comment) throws JSchException {
			super(marker, host, type, key, comment);
			if (this.host.startsWith(HASH_MAGIC) &&
					this.host.substring(HASH_MAGIC.length()).indexOf(HASH_DELIM) > 0) {
				final String data = this.host.substring(HASH_MAGIC.length());
				final String _salt = data.substring(0, data.indexOf(HASH_DELIM));
				final String _hash = data.substring(data.indexOf(HASH_DELIM) + 1);
				this.salt = Util.fromBase64(Util.str2byte(_salt), 0, _salt.length());
				this.hash = Util.fromBase64(Util.str2byte(_hash), 0, _hash.length());
				if (this.salt.length != 20 || // block size of hmac-sha1
						this.hash.length != 20) {
					this.salt = null;
					this.hash = null;
					return;
				}
				this.hashed = true;
			}
		}

		@Override
		boolean isMatched(final String _host) {
			if (!this.hashed) {
				return super.isMatched(_host);
			}
			final MAC macsha1 = KnownHosts.this.getHMACSHA1();
			try {
				synchronized (macsha1) {
					macsha1.init(this.salt);
					final byte[] foo = Util.str2byte(_host);
					macsha1.update(foo, 0, foo.length);
					final byte[] bar = new byte[macsha1.getBlockSize()];
					macsha1.doFinal(bar, 0);
					return Util.array_equals(this.hash, bar);
				}
			} catch (final Exception e) {
				System.out.println(e);
			}
			return false;
		}

		boolean isHashed() {
			return this.hashed;
		}

		void hash() {
			if (this.hashed) {
				return;
			}
			final MAC macsha1 = KnownHosts.this.getHMACSHA1();
			if (this.salt == null) {
				final Random random = Session.random;
				synchronized (random) {
					this.salt = new byte[macsha1.getBlockSize()];
					random.fill(this.salt, 0, this.salt.length);
				}
			}
			try {
				synchronized (macsha1) {
					macsha1.init(this.salt);
					final byte[] foo = Util.str2byte(this.host);
					macsha1.update(foo, 0, foo.length);
					this.hash = new byte[macsha1.getBlockSize()];
					macsha1.doFinal(this.hash, 0);
				}
			} catch (final Exception e) {}
			this.host = HASH_MAGIC + Util.byte2str(Util.toBase64(this.salt, 0, this.salt.length)) +
					HASH_DELIM + Util.byte2str(Util.toBase64(this.hash, 0, this.hash.length));
			this.hashed = true;
		}
	}
}
