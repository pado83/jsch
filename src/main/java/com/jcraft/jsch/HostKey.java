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

public class HostKey {

	private static final byte[][] names = {
			Util.str2byte("ssh-dss"),
			Util.str2byte("ssh-rsa"),
			Util.str2byte("ecdsa-sha2-nistp256"),
			Util.str2byte("ecdsa-sha2-nistp384"),
			Util.str2byte("ecdsa-sha2-nistp521")
	};

	protected static final int GUESS = 0;
	public static final int SSHDSS = 1;
	public static final int SSHRSA = 2;
	public static final int ECDSA256 = 3;
	public static final int ECDSA384 = 4;
	public static final int ECDSA521 = 5;
	static final int UNKNOWN = 6;

	protected String marker;
	protected String host;
	protected int type;
	protected byte[] key;
	protected String comment;

	public HostKey(final String host, final byte[] key) throws JSchException {
		this(host, GUESS, key);
	}

	public HostKey(final String host, final int type, final byte[] key) throws JSchException {
		this(host, type, key, null);
	}

	public HostKey(final String host, final int type, final byte[] key, final String comment) throws JSchException {
		this("", host, type, key, comment);
	}

	public HostKey(final String marker, final String host, final int type, final byte[] key, final String comment) throws JSchException {
		this.marker = marker;
		this.host = host;
		if (type == GUESS) {
			if (key[8] == 'd') {
				this.type = SSHDSS;
			} else if (key[8] == 'r') {
				this.type = SSHRSA;
			} else if (key[8] == 'a' && key[20] == '2') {
				this.type = ECDSA256;
			} else if (key[8] == 'a' && key[20] == '3') {
				this.type = ECDSA384;
			} else if (key[8] == 'a' && key[20] == '5') {
				this.type = ECDSA521;
			} else {
				throw new JSchException("invalid key type");
			}
		} else {
			this.type = type;
		}
		this.key = key;
		this.comment = comment;
	}

	public String getHost() {
		return this.host;
	}

	public String getType() {
		if (this.type == SSHDSS ||
				this.type == SSHRSA ||
				this.type == ECDSA256 ||
				this.type == ECDSA384 ||
				this.type == ECDSA521) {
			return Util.byte2str(names[this.type - 1]);
		}
		return "UNKNOWN";
	}

	protected static int name2type(final String name) {
		for (int i = 0; i < names.length; i++) {
			if (Util.byte2str(names[i]).equals(name)) {
				return i + 1;
			}
		}
		return UNKNOWN;
	}

	public String getKey() {
		return Util.byte2str(Util.toBase64(this.key, 0, this.key.length));
	}

	public String getFingerPrint(final JSch jsch) {
		HASH hash = null;
		try {
			final Class<?> c = Class.forName(JSch.getConfig("md5"));
			hash = (HASH) c.newInstance();
		} catch (final Exception e) {
			System.err.println("getFingerPrint: " + e);
		}
		return Util.getFingerPrint(hash, this.key);
	}

	public String getComment() {
		return this.comment;
	}

	public String getMarker() {
		return this.marker;
	}

	boolean isMatched(final String _host) {
		return this.isIncluded(_host);
	}

	private boolean isIncluded(final String _host) {
		int i = 0;
		final String hosts = this.host;
		final int hostslen = hosts.length();
		final int hostlen = _host.length();
		int j;
		while (i < hostslen) {
			j = hosts.indexOf(',', i);
			if (j == -1) {
				if (hostlen != hostslen - i) {
					return false;
				}
				return hosts.regionMatches(true, i, _host, 0, hostlen);
			}
			if (hostlen == j - i) {
				if (hosts.regionMatches(true, i, _host, 0, hostlen)) {
					return true;
				}
			}
			i = j + 1;
		}
		return false;
	}
}
