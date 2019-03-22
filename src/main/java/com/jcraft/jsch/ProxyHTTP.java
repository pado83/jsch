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
import java.net.Socket;

public class ProxyHTTP implements Proxy {

	private static int DEFAULTPORT = 80;
	private final String proxy_host;
	private final int proxy_port;
	private InputStream in;
	private OutputStream out;
	private Socket socket;

	private String user;
	private String passwd;

	public ProxyHTTP(final String proxy_host) {
		int port = DEFAULTPORT;
		String host = proxy_host;
		if (proxy_host.indexOf(':') != -1) {
			try {
				host = proxy_host.substring(0, proxy_host.indexOf(':'));
				port = Integer.parseInt(proxy_host.substring(proxy_host.indexOf(':') + 1));
			} catch (final Exception e) {}
		}
		this.proxy_host = host;
		this.proxy_port = port;
	}

	public ProxyHTTP(final String proxy_host, final int proxy_port) {
		this.proxy_host = proxy_host;
		this.proxy_port = proxy_port;
	}

	public void setUserPasswd(final String user, final String passwd) {
		this.user = user;
		this.passwd = passwd;
	}

	@Override
	public void connect(final SocketFactory socket_factory, final String host, final int port, final int timeout) throws JSchException {
		try {
			if (socket_factory == null) {
				this.socket = Util.createSocket(this.proxy_host, this.proxy_port, timeout);
				this.in = this.socket.getInputStream();
				this.out = this.socket.getOutputStream();
			} else {
				this.socket = socket_factory.createSocket(this.proxy_host, this.proxy_port);
				this.in = socket_factory.getInputStream(this.socket);
				this.out = socket_factory.getOutputStream(this.socket);
			}
			if (timeout > 0) {
				this.socket.setSoTimeout(timeout);
			}
			this.socket.setTcpNoDelay(true);

			this.out.write(Util.str2byte("CONNECT " + host + ":" + port + " HTTP/1.0\r\n"));

			if (this.user != null && this.passwd != null) {
				byte[] code = Util.str2byte(this.user + ":" + this.passwd);
				code = Util.toBase64(code, 0, code.length);
				this.out.write(Util.str2byte("Proxy-Authorization: Basic "));
				this.out.write(code);
				this.out.write(Util.str2byte("\r\n"));
			}

			this.out.write(Util.str2byte("\r\n"));
			this.out.flush();

			int foo = 0;

			final StringBuffer sb = new StringBuffer();
			while (foo >= 0) {
				foo = this.in.read();
				if (foo != 13) {
					sb.append((char) foo);
					continue;
				}
				foo = this.in.read();
				if (foo != 10) {
					continue;
				}
				break;
			}
			if (foo < 0) {
				throw new IOException();
			}

			final String response = sb.toString();
			String reason = "Unknow reason";
			int code = -1;
			try {
				foo = response.indexOf(' ');
				final int bar = response.indexOf(' ', foo + 1);
				code = Integer.parseInt(response.substring(foo + 1, bar));
				reason = response.substring(bar + 1);
			} catch (final Exception e) {}
			if (code != 200) {
				throw new IOException("proxy error: " + reason);
			}

			/*
			 * while(foo>=0){
			 * foo=in.read(); if(foo!=13) continue;
			 * foo=in.read(); if(foo!=10) continue;
			 * foo=in.read(); if(foo!=13) continue;
			 * foo=in.read(); if(foo!=10) continue;
			 * break;
			 * }
			 */

			int count = 0;
			while (true) {
				count = 0;
				while (foo >= 0) {
					foo = this.in.read();
					if (foo != 13) {
						count++;
						continue;
					}
					foo = this.in.read();
					if (foo != 10) {
						continue;
					}
					break;
				}
				if (foo < 0) {
					throw new IOException();
				}
				if (count == 0) {
					break;
				}
			}
		} catch (final RuntimeException e) {
			throw e;
		} catch (final Exception e) {
			try {
				if (this.socket != null) {
					this.socket.close();
				}
			} catch (final Exception eee) {}
			final String message = "ProxyHTTP: " + e.toString();
			if (e instanceof Throwable) {
				throw new JSchException(message, e);
			}
			throw new JSchException(message);
		}
	}

	@Override
	public InputStream getInputStream() {
		return this.in;
	}

	@Override
	public OutputStream getOutputStream() {
		return this.out;
	}

	@Override
	public Socket getSocket() {
		return this.socket;
	}

	@Override
	public void close() {
		try {
			if (this.in != null) {
				this.in.close();
			}
			if (this.out != null) {
				this.out.close();
			}
			if (this.socket != null) {
				this.socket.close();
			}
		} catch (final Exception e) {}
		this.in = null;
		this.out = null;
		this.socket = null;
	}

	public static int getDefaultPort() {
		return DEFAULTPORT;
	}
}
