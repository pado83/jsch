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

class UserAuthPassword extends UserAuth {

	private final int SSH_MSG_USERAUTH_PASSWD_CHANGEREQ = 60;

	@Override
	public boolean start(final Session session) throws Exception {
		super.start(session);

		byte[] password = session.password;
		String dest = this.username + "@" + session.host;
		if (session.port != 22) {
			dest += (":" + session.port);
		}

		try {

			while (true) {

				if (session.auth_failures >= session.max_auth_tries) {
					return false;
				}

				if (password == null) {
					if (this.userinfo == null) {
						// throw new JSchException("USERAUTH fail");
						return false;
					}
					if (!this.userinfo.promptPassword("Password for " + dest)) {
						throw new JSchAuthCancelException("password");
						// break;
					}

					final String _password = this.userinfo.getPassword();
					if (_password == null) {
						throw new JSchAuthCancelException("password");
						// break;
					}
					password = Util.str2byte(_password);
				}

				byte[] _username = null;
				_username = Util.str2byte(this.username);

				// send
				// byte SSH_MSG_USERAUTH_REQUEST(50)
				// string user name
				// string service name ("ssh-connection")
				// string "password"
				// boolen FALSE
				// string plaintext password (ISO-10646 UTF-8)
				this.packet.reset();
				this.buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
				this.buf.putString(_username);
				this.buf.putString(Util.str2byte("ssh-connection"));
				this.buf.putString(Util.str2byte("password"));
				this.buf.putByte((byte) 0);
				this.buf.putString(password);
				session.write(this.packet);

				loop: while (true) {
					this.buf = session.read(this.buf);
					final int command = this.buf.getCommand() & 0xff;

					if (command == SSH_MSG_USERAUTH_SUCCESS) {
						return true;
					}
					if (command == SSH_MSG_USERAUTH_BANNER) {
						this.buf.getInt();
						this.buf.getByte();
						this.buf.getByte();
						final byte[] _message = this.buf.getString();
						final byte[] lang = this.buf.getString();
						final String message = Util.byte2str(_message);
						if (this.userinfo != null) {
							this.userinfo.showMessage(message);
						}
						continue loop;
					}
					if (command == this.SSH_MSG_USERAUTH_PASSWD_CHANGEREQ) {
						this.buf.getInt();
						this.buf.getByte();
						this.buf.getByte();
						final byte[] instruction = this.buf.getString();
						final byte[] tag = this.buf.getString();
						if (this.userinfo == null ||
								!(this.userinfo instanceof UIKeyboardInteractive)) {
							if (this.userinfo != null) {
								this.userinfo.showMessage("Password must be changed.");
							}
							return false;
						}

						final UIKeyboardInteractive kbi = (UIKeyboardInteractive) this.userinfo;
						String[] response;
						final String name = "Password Change Required";
						final String[] prompt = { "New Password: " };
						final boolean[] echo = { false };
						response = kbi.promptKeyboardInteractive(dest,
								name,
								Util.byte2str(instruction),
								prompt,
								echo);
						if (response == null) {
							throw new JSchAuthCancelException("password");
						}

						final byte[] newpassword = Util.str2byte(response[0]);

						// send
						// byte SSH_MSG_USERAUTH_REQUEST(50)
						// string user name
						// string service name ("ssh-connection")
						// string "password"
						// boolen TRUE
						// string plaintext old password (ISO-10646 UTF-8)
						// string plaintext new password (ISO-10646 UTF-8)
						this.packet.reset();
						this.buf.putByte((byte) SSH_MSG_USERAUTH_REQUEST);
						this.buf.putString(_username);
						this.buf.putString(Util.str2byte("ssh-connection"));
						this.buf.putString(Util.str2byte("password"));
						this.buf.putByte((byte) 1);
						this.buf.putString(password);
						this.buf.putString(newpassword);
						Util.bzero(newpassword);
						response = null;
						session.write(this.packet);
						continue loop;
					}
					if (command == SSH_MSG_USERAUTH_FAILURE) {
						this.buf.getInt();
						this.buf.getByte();
						this.buf.getByte();
						final byte[] foo = this.buf.getString();
						final int partial_success = this.buf.getByte();
						// System.err.println(new String(foo)+
						// " partial_success:"+(partial_success!=0));
						if (partial_success != 0) {
							throw new JSchPartialAuthException(Util.byte2str(foo));
						}
						session.auth_failures++;
						break;
					} else {
						// System.err.println("USERAUTH fail ("+buf.getCommand()+")");
						// throw new JSchException("USERAUTH fail ("+buf.getCommand()+")");
						return false;
					}
				}

				if (password != null) {
					Util.bzero(password);
					password = null;
				}

			}

		} finally {
			if (password != null) {
				Util.bzero(password);
				password = null;
			}
		}

		// throw new JSchException("USERAUTH fail");
		// return false;
	}
}
