/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2006-2018 ymnk, JCraft,Inc. All rights reserved.

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

import java.util.Vector;

class ChannelAgentForwarding extends Channel {

	static private final int LOCAL_WINDOW_SIZE_MAX = 0x20000;
	static private final int LOCAL_MAXIMUM_PACKET_SIZE = 0x4000;

	private final byte SSH_AGENTC_REQUEST_RSA_IDENTITIES = 1;
	private final byte SSH_AGENT_RSA_IDENTITIES_ANSWER = 2;
	private final byte SSH_AGENTC_RSA_CHALLENGE = 3;
	private final byte SSH_AGENT_RSA_RESPONSE = 4;
	private final byte SSH_AGENT_FAILURE = 5;
	private final byte SSH_AGENT_SUCCESS = 6;
	private final byte SSH_AGENTC_ADD_RSA_IDENTITY = 7;
	private final byte SSH_AGENTC_REMOVE_RSA_IDENTITY = 8;
	private final byte SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES = 9;

	private final byte SSH2_AGENTC_REQUEST_IDENTITIES = 11;
	private final byte SSH2_AGENT_IDENTITIES_ANSWER = 12;
	private final byte SSH2_AGENTC_SIGN_REQUEST = 13;
	private final byte SSH2_AGENT_SIGN_RESPONSE = 14;
	private final byte SSH2_AGENTC_ADD_IDENTITY = 17;
	private final byte SSH2_AGENTC_REMOVE_IDENTITY = 18;
	private final byte SSH2_AGENTC_REMOVE_ALL_IDENTITIES = 19;
	private final byte SSH2_AGENT_FAILURE = 30;

	boolean init = true;

	private Buffer rbuf = null;
	private Buffer wbuf = null;
	private Packet packet = null;
	private Buffer mbuf = null;

	ChannelAgentForwarding() {
		super();

		this.setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);

		this.type = Util.str2byte("auth-agent@openssh.com");
		this.rbuf = new Buffer();
		this.rbuf.reset();
		// wbuf=new Buffer(rmpsize);
		// packet=new Packet(wbuf);
		this.mbuf = new Buffer();
		this.connected = true;
	}

	@Override
	public void run() {
		try {
			this.sendOpenConfirmation();
		} catch (final Exception e) {
			this.close = true;
			this.disconnect();
		}
	}

	@Override
	void write(final byte[] foo, final int s, final int l) throws java.io.IOException {

		if (this.packet == null) {
			this.wbuf = new Buffer(this.rmpsize);
			this.packet = new Packet(this.wbuf);
		}

		this.rbuf.shift();
		if (this.rbuf.buffer.length < this.rbuf.index + l) {
			final byte[] newbuf = new byte[this.rbuf.s + l];
			System.arraycopy(this.rbuf.buffer, 0, newbuf, 0, this.rbuf.buffer.length);
			this.rbuf.buffer = newbuf;
		}

		this.rbuf.putByte(foo, s, l);

		final int mlen = this.rbuf.getInt();
		if (mlen > this.rbuf.getLength()) {
			this.rbuf.s -= 4;
			return;
		}

		final int typ = this.rbuf.getByte();

		Session _session = null;
		try {
			_session = this.getSession();
		} catch (final JSchException e) {
			throw new java.io.IOException(e.toString());
		}

		final IdentityRepository irepo = _session.getIdentityRepository();
		final UserInfo userinfo = _session.getUserInfo();

		this.mbuf.reset();

		if (typ == this.SSH2_AGENTC_REQUEST_IDENTITIES) {
			this.mbuf.putByte(this.SSH2_AGENT_IDENTITIES_ANSWER);
			final Vector identities = irepo.getIdentities();
			synchronized (identities) {
				int count = 0;
				for (int i = 0; i < identities.size(); i++) {
					final Identity identity = (Identity) (identities.elementAt(i));
					if (identity.getPublicKeyBlob() != null) {
						count++;
					}
				}
				this.mbuf.putInt(count);
				for (int i = 0; i < identities.size(); i++) {
					final Identity identity = (Identity) (identities.elementAt(i));
					final byte[] pubkeyblob = identity.getPublicKeyBlob();
					if (pubkeyblob == null) {
						continue;
					}
					this.mbuf.putString(pubkeyblob);
					this.mbuf.putString(Util.empty);
				}
			}
		} else if (typ == this.SSH_AGENTC_REQUEST_RSA_IDENTITIES) {
			this.mbuf.putByte(this.SSH_AGENT_RSA_IDENTITIES_ANSWER);
			this.mbuf.putInt(0);
		} else if (typ == this.SSH2_AGENTC_SIGN_REQUEST) {
			final byte[] blob = this.rbuf.getString();
			final byte[] data = this.rbuf.getString();
			final int flags = this.rbuf.getInt();

			// if((flags & 1)!=0){ //SSH_AGENT_OLD_SIGNATURE // old OpenSSH 2.0, 2.1
			// datafellows = SSH_BUG_SIGBLOB;
			// }

			final Vector identities = irepo.getIdentities();
			Identity identity = null;
			synchronized (identities) {
				for (int i = 0; i < identities.size(); i++) {
					final Identity _identity = (Identity) (identities.elementAt(i));
					if (_identity.getPublicKeyBlob() == null) {
						continue;
					}
					if (!Util.array_equals(blob, _identity.getPublicKeyBlob())) {
						continue;
					}
					if (_identity.isEncrypted()) {
						if (userinfo == null) {
							continue;
						}
						while (_identity.isEncrypted()) {
							if (!userinfo.promptPassphrase("Passphrase for " + _identity.getName())) {
								break;
							}

							final String _passphrase = userinfo.getPassphrase();
							if (_passphrase == null) {
								break;
							}

							final byte[] passphrase = Util.str2byte(_passphrase);
							try {
								if (_identity.setPassphrase(passphrase)) {
									break;
								}
							} catch (final JSchException e) {
								break;
							}
						}
					}

					if (!_identity.isEncrypted()) {
						identity = _identity;
						break;
					}
				}
			}

			byte[] signature = null;

			if (identity != null) {
				signature = identity.getSignature(data);
			}

			if (signature == null) {
				this.mbuf.putByte(this.SSH2_AGENT_FAILURE);
			} else {
				this.mbuf.putByte(this.SSH2_AGENT_SIGN_RESPONSE);
				this.mbuf.putString(signature);
			}
		} else if (typ == this.SSH2_AGENTC_REMOVE_IDENTITY) {
			final byte[] blob = this.rbuf.getString();
			irepo.remove(blob);
			this.mbuf.putByte(this.SSH_AGENT_SUCCESS);
		} else if (typ == this.SSH_AGENTC_REMOVE_ALL_RSA_IDENTITIES) {
			this.mbuf.putByte(this.SSH_AGENT_SUCCESS);
		} else if (typ == this.SSH2_AGENTC_REMOVE_ALL_IDENTITIES) {
			irepo.removeAll();
			this.mbuf.putByte(this.SSH_AGENT_SUCCESS);
		} else if (typ == this.SSH2_AGENTC_ADD_IDENTITY) {
			final int fooo = this.rbuf.getLength();
			final byte[] tmp = new byte[fooo];
			this.rbuf.getByte(tmp);
			final boolean result = irepo.add(tmp);
			this.mbuf.putByte(result ? this.SSH_AGENT_SUCCESS : this.SSH_AGENT_FAILURE);
		} else {
			this.rbuf.skip(this.rbuf.getLength() - 1);
			this.mbuf.putByte(this.SSH_AGENT_FAILURE);
		}

		final byte[] response = new byte[this.mbuf.getLength()];
		this.mbuf.getByte(response);
		this.send(response);
	}

	private void send(final byte[] message) {
		this.packet.reset();
		this.wbuf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
		this.wbuf.putInt(this.recipient);
		this.wbuf.putInt(4 + message.length);
		this.wbuf.putString(message);

		try {
			this.getSession().write(this.packet, this, 4 + message.length);
		} catch (final Exception e) {}
	}

	@Override
	void eof_remote() {
		super.eof_remote();
		this.eof();
	}
}
