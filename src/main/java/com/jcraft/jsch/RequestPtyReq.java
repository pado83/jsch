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

class RequestPtyReq extends Request {

	private String ttype = "vt100";
	private int tcol = 80;
	private int trow = 24;
	private int twp = 640;
	private int thp = 480;

	private byte[] terminal_mode = Util.empty;

	void setCode(final String cookie) {}

	void setTType(final String ttype) {
		this.ttype = ttype;
	}

	void setTerminalMode(final byte[] terminal_mode) {
		this.terminal_mode = terminal_mode;
	}

	void setTSize(final int tcol, final int trow, final int twp, final int thp) {
		this.tcol = tcol;
		this.trow = trow;
		this.twp = twp;
		this.thp = thp;
	}

	@Override
	public void request(final Session session, final Channel channel) throws Exception {
		super.request(session, channel);

		final Buffer buf = new Buffer();
		final Packet packet = new Packet(buf);

		packet.reset();
		buf.putByte((byte) Session.SSH_MSG_CHANNEL_REQUEST);
		buf.putInt(channel.getRecipient());
		buf.putString(Util.str2byte("pty-req"));
		buf.putByte((byte) (this.waitForReply() ? 1 : 0));
		buf.putString(Util.str2byte(this.ttype));
		buf.putInt(this.tcol);
		buf.putInt(this.trow);
		buf.putInt(this.twp);
		buf.putInt(this.thp);
		buf.putString(this.terminal_mode);
		this.write(packet);
	}
}
