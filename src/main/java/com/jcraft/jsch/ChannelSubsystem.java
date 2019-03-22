/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2005-2018 ymnk, JCraft,Inc. All rights reserved.

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

public class ChannelSubsystem extends ChannelSession {

	boolean xforwading = false;
	boolean pty = false;
	boolean want_reply = true;
	String subsystem = "";

	@Override
	public void setXForwarding(final boolean foo) {
		this.xforwading = foo;
	}

	@Override
	public void setPty(final boolean foo) {
		this.pty = foo;
	}

	public void setWantReply(final boolean foo) {
		this.want_reply = foo;
	}

	public void setSubsystem(final String foo) {
		this.subsystem = foo;
	}

	@Override
	public void start() throws JSchException {
		final Session _session = this.getSession();
		try {
			Request request;
			if (this.xforwading) {
				request = new RequestX11();
				request.request(_session, this);
			}
			if (this.pty) {
				request = new RequestPtyReq();
				request.request(_session, this);
			}
			request = new RequestSubsystem();
			((RequestSubsystem) request).request(_session, this, this.subsystem, this.want_reply);
		} catch (final Exception e) {
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			throw new JSchException("ChannelSubsystem", e);
		}
		if (this.io.in != null) {
			this.thread = new Thread(this);
			this.thread.setName("Subsystem for " + _session.host);
			if (_session.daemon_thread) {
				this.thread.setDaemon(_session.daemon_thread);
			}
			this.thread.start();
		}
	}

	@Override
	void init() throws JSchException {
		this.io.setInputStream(this.getSession().in);
		this.io.setOutputStream(this.getSession().out);
	}

	public void setErrStream(final java.io.OutputStream out) {
		this.setExtOutputStream(out);
	}

	public java.io.InputStream getErrStream() throws java.io.IOException {
		return this.getExtInputStream();
	}
}
