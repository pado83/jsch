/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2013-2018 ymnk, JCraft,Inc. All rights reserved.

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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.util.Hashtable;
import java.util.Vector;

/**
 * This class implements ConfigRepository interface, and parses
 * OpenSSH's configuration file. The following keywords will be recognized,
 * <ul>
 * <li>Host</li>
 * <li>User</li>
 * <li>Hostname</li>
 * <li>Port</li>
 * <li>PreferredAuthentications</li>
 * <li>IdentityFile</li>
 * <li>NumberOfPasswordPrompts</li>
 * <li>ConnectTimeout</li>
 * <li>HostKeyAlias</li>
 * <li>UserKnownHostsFile</li>
 * <li>KexAlgorithms</li>
 * <li>HostKeyAlgorithms</li>
 * <li>Ciphers</li>
 * <li>Macs</li>
 * <li>Compression</li>
 * <li>CompressionLevel</li>
 * <li>ForwardAgent</li>
 * <li>RequestTTY</li>
 * <li>ServerAliveInterval</li>
 * <li>LocalForward</li>
 * <li>RemoteForward</li>
 * <li>ClearAllForwardings</li>
 * </ul>
 *
 * @see ConfigRepository
 */
public class OpenSSHConfig implements ConfigRepository {

	/**
	 * Parses the given string, and returns an instance of ConfigRepository.
	 *
	 * @param conf string, which includes OpenSSH's config
	 * @return an instanceof OpenSSHConfig
	 */
	public static OpenSSHConfig parse(final String conf) throws IOException {
		final Reader r = new StringReader(conf);
		try {
			return new OpenSSHConfig(r);
		} finally {
			r.close();
		}
	}

	/**
	 * Parses the given file, and returns an instance of ConfigRepository.
	 *
	 * @param file OpenSSH's config file
	 * @return an instanceof OpenSSHConfig
	 */
	public static OpenSSHConfig parseFile(final String file) throws IOException {
		final Reader r = new FileReader(Util.checkTilde(file));
		try {
			return new OpenSSHConfig(r);
		} finally {
			r.close();
		}
	}

	OpenSSHConfig(final Reader r) throws IOException {
		this._parse(r);
	}

	private final Hashtable<String, Vector<String[]>> config = new Hashtable<String, Vector<String[]>>();
	private final Vector<String> hosts = new Vector<String>();

	private void _parse(final Reader r) throws IOException {
		final BufferedReader br = new BufferedReader(r);

		String host = "";
		Vector/* <String[]> */<String[]> kv = new Vector<String[]>();
		String l = null;

		while ((l = br.readLine()) != null) {
			l = l.trim();
			if (l.length() == 0 || l.startsWith("#")) {
				continue;
			}

			final String[] key_value = l.split("[= \t]", 2);
			for (int i = 0; i < key_value.length; i++) {
				key_value[i] = key_value[i].trim();
			}

			if (key_value.length <= 1) {
				continue;
			}

			if (key_value[0].equals("Host")) {
				this.config.put(host, kv);
				this.hosts.addElement(host);
				host = key_value[1];
				kv = new Vector<String[]>();
			} else {
				kv.addElement(key_value);
			}
		}
		this.config.put(host, kv);
		this.hosts.addElement(host);
	}

	@Override
	public Config getConfig(final String host) {
		return new MyConfig(host);
	}

	private static final Hashtable<String, String> keymap = new Hashtable<String, String>();
	static {
		keymap.put("kex", "KexAlgorithms");
		keymap.put("server_host_key", "HostKeyAlgorithms");
		keymap.put("cipher.c2s", "Ciphers");
		keymap.put("cipher.s2c", "Ciphers");
		keymap.put("mac.c2s", "Macs");
		keymap.put("mac.s2c", "Macs");
		keymap.put("compression.s2c", "Compression");
		keymap.put("compression.c2s", "Compression");
		keymap.put("compression_level", "CompressionLevel");
		keymap.put("MaxAuthTries", "NumberOfPasswordPrompts");
	}

	class MyConfig implements Config {

		private final Vector<Vector<String[]>> _configs = new Vector<Vector<String[]>>();

		MyConfig(final String host) {
			this._configs.addElement(OpenSSHConfig.this.config.get(""));

			final byte[] _host = Util.str2byte(host);
			if (OpenSSHConfig.this.hosts.size() > 1) {
				for (int i = 1; i < OpenSSHConfig.this.hosts.size(); i++) {
					final String patterns[] = OpenSSHConfig.this.hosts.elementAt(i).split("[ \t]");
					for (int j = 0; j < patterns.length; j++) {
						boolean negate = false;
						String foo = patterns[j].trim();
						if (foo.startsWith("!")) {
							negate = true;
							foo = foo.substring(1).trim();
						}
						if (Util.glob(Util.str2byte(foo), _host)) {
							if (!negate) {
								this._configs.addElement(OpenSSHConfig.this.config.get(OpenSSHConfig.this.hosts.elementAt(i)));
							}
						} else if (negate) {
							this._configs.addElement(OpenSSHConfig.this.config.get(OpenSSHConfig.this.hosts.elementAt(i)));
						}
					}
				}
			}
		}

		private String find(String key) {
			if (keymap.get(key) != null) {
				key = keymap.get(key);
			}
			key = key.toUpperCase();
			String value = null;
			for (int i = 0; i < this._configs.size(); i++) {
				final Vector<?> v = this._configs.elementAt(i);
				for (int j = 0; j < v.size(); j++) {
					final String[] kv = (String[]) v.elementAt(j);
					if (kv[0].toUpperCase().equals(key)) {
						value = kv[1];
						break;
					}
				}
				if (value != null) {
					break;
				}
			}
			// TODO: The following change should be applied,
			// but it is breaking changes.
			// The consensus is required to enable it.
			/*
			 * if(value!=null &&
			 * (key.equals("SERVERALIVEINTERVAL") ||
			 * key.equals("CONNECTTIMEOUT"))){
			 * try {
			 * int timeout = Integer.parseInt(value);
			 * value = Integer.toString(timeout*1000);
			 * } catch (NumberFormatException e) {
			 * }
			 * }
			 */
			return value;
		}

		private String[] multiFind(String key) {
			key = key.toUpperCase();
			final Vector<String> value = new Vector<String>();
			for (int i = 0; i < this._configs.size(); i++) {
				final Vector<?> v = this._configs.elementAt(i);
				for (int j = 0; j < v.size(); j++) {
					final String[] kv = (String[]) v.elementAt(j);
					if (kv[0].toUpperCase().equals(key)) {
						final String foo = kv[1];
						if (foo != null) {
							value.remove(foo);
							value.addElement(foo);
						}
					}
				}
			}
			final String[] result = new String[value.size()];
			value.toArray(result);
			return result;
		}

		@Override
		public String getHostname() {
			return this.find("Hostname");
		}

		@Override
		public String getUser() {
			return this.find("User");
		}

		@Override
		public int getPort() {
			final String foo = this.find("Port");
			int port = -1;
			try {
				port = Integer.parseInt(foo);
			} catch (final NumberFormatException e) {
				// wrong format
			}
			return port;
		}

		@Override
		public String getValue(final String key) {
			if (key.equals("compression.s2c") ||
					key.equals("compression.c2s")) {
				final String foo = this.find(key);
				if (foo == null || foo.equals("no")) {
					return "none,zlib@openssh.com,zlib";
				}
				return "zlib@openssh.com,zlib,none";
			}
			return this.find(key);
		}

		@Override
		public String[] getValues(final String key) {
			return this.multiFind(key);
		}
	}
}
