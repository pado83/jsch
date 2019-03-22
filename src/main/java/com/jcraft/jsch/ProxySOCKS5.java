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

/*
 This file depends on following documents,
   - RFC 1928  SOCKS Protocol Verseion 5
   - RFC 1929  Username/Password Authentication for SOCKS V5.
 */

package com.jcraft.jsch;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class ProxySOCKS5 implements Proxy {

	private static int DEFAULTPORT = 1080;
	private final String proxy_host;
	private final int proxy_port;
	private InputStream in;
	private OutputStream out;
	private Socket socket;
	private String user;
	private String passwd;

	public ProxySOCKS5(final String proxy_host) {
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

	public ProxySOCKS5(final String proxy_host, final int proxy_port) {
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
				// socket=new Socket(proxy_host, proxy_port);
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

			final byte[] buf = new byte[1024];
			int index = 0;

			/*
			 * +----+----------+----------+
			 * |VER | NMETHODS | METHODS |
			 * +----+----------+----------+
			 * | 1 | 1 | 1 to 255 |
			 * +----+----------+----------+
			 *
			 * The VER field is set to X'05' for this version of the protocol. The
			 * NMETHODS field contains the number of method identifier octets that
			 * appear in the METHODS field.
			 *
			 * The values currently defined for METHOD are:
			 *
			 * o X'00' NO AUTHENTICATION REQUIRED
			 * o X'01' GSSAPI
			 * o X'02' USERNAME/PASSWORD
			 * o X'03' to X'7F' IANA ASSIGNED
			 * o X'80' to X'FE' RESERVED FOR PRIVATE METHODS
			 * o X'FF' NO ACCEPTABLE METHODS
			 */

			buf[index++] = 5;

			buf[index++] = 2;
			buf[index++] = 0; // NO AUTHENTICATION REQUIRED
			buf[index++] = 2; // USERNAME/PASSWORD

			this.out.write(buf, 0, index);

			/*
			 * The server selects from one of the methods given in METHODS, and
			 * sends a METHOD selection message:
			 *
			 * +----+--------+
			 * |VER | METHOD |
			 * +----+--------+
			 * | 1 | 1 |
			 * +----+--------+
			 */
			// in.read(buf, 0, 2);
			ProxySOCKS5.fill(this.in, buf, 2);

			boolean check = false;
			switch (buf[1] & 0xff) {
				case 0: // NO AUTHENTICATION REQUIRED
					check = true;
					break;
				case 2: // USERNAME/PASSWORD
					if (this.user == null || this.passwd == null) {
						break;
					}

					/*
					 * Once the SOCKS V5 server has started, and the client has selected the
					 * Username/Password Authentication protocol, the Username/Password
					 * subnegotiation begins. This begins with the client producing a
					 * Username/Password request:
					 *
					 * +----+------+----------+------+----------+
					 * |VER | ULEN | UNAME | PLEN | PASSWD |
					 * +----+------+----------+------+----------+
					 * | 1 | 1 | 1 to 255 | 1 | 1 to 255 |
					 * +----+------+----------+------+----------+
					 *
					 * The VER field contains the current version of the subnegotiation,
					 * which is X'01'. The ULEN field contains the length of the UNAME field
					 * that follows. The UNAME field contains the username as known to the
					 * source operating system. The PLEN field contains the length of the
					 * PASSWD field that follows. The PASSWD field contains the password
					 * association with the given UNAME.
					 */
					index = 0;
					buf[index++] = 1;
					buf[index++] = (byte) this.user.length();
					System.arraycopy(Util.str2byte(this.user), 0, buf, index, this.user.length());
					index += this.user.length();
					buf[index++] = (byte) this.passwd.length();
					System.arraycopy(Util.str2byte(this.passwd), 0, buf, index, this.passwd.length());
					index += this.passwd.length();

					this.out.write(buf, 0, index);

					/*
					 * The server verifies the supplied UNAME and PASSWD, and sends the
					 * following response:
					 *
					 * +----+--------+
					 * |VER | STATUS |
					 * +----+--------+
					 * | 1 | 1 |
					 * +----+--------+
					 *
					 * A STATUS field of X'00' indicates success. If the server returns a
					 * `failure' (STATUS value other than X'00') status, it MUST close the
					 * connection.
					 */
					// in.read(buf, 0, 2);
					ProxySOCKS5.fill(this.in, buf, 2);
					if (buf[1] == 0) {
						check = true;
					}
					break;
				default:
			}

			if (!check) {
				try {
					this.socket.close();
				} catch (final Exception eee) {}
				throw new JSchException("fail in SOCKS5 proxy");
			}

			/*
			 * The SOCKS request is formed as follows:
			 *
			 * +----+-----+-------+------+----------+----------+
			 * |VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT |
			 * +----+-----+-------+------+----------+----------+
			 * | 1 | 1 | X'00' | 1 | Variable | 2 |
			 * +----+-----+-------+------+----------+----------+
			 *
			 * Where:
			 *
			 * o VER protocol version: X'05'
			 * o CMD
			 * o CONNECT X'01'
			 * o BIND X'02'
			 * o UDP ASSOCIATE X'03'
			 * o RSV RESERVED
			 * o ATYP address type of following address
			 * o IP V4 address: X'01'
			 * o DOMAINNAME: X'03'
			 * o IP V6 address: X'04'
			 * o DST.ADDR desired destination address
			 * o DST.PORT desired destination port in network octet
			 * order
			 */

			index = 0;
			buf[index++] = 5;
			buf[index++] = 1; // CONNECT
			buf[index++] = 0;

			final byte[] hostb = Util.str2byte(host);
			final int len = hostb.length;
			buf[index++] = 3; // DOMAINNAME
			buf[index++] = (byte) len;
			System.arraycopy(hostb, 0, buf, index, len);
			index += len;
			buf[index++] = (byte) (port >>> 8);
			buf[index++] = (byte) (port & 0xff);

			this.out.write(buf, 0, index);

			/*
			 * The SOCKS request information is sent by the client as soon as it has
			 * established a connection to the SOCKS server, and completed the
			 * authentication negotiations. The server evaluates the request, and
			 * returns a reply formed as follows:
			 *
			 * +----+-----+-------+------+----------+----------+
			 * |VER | REP | RSV | ATYP | BND.ADDR | BND.PORT |
			 * +----+-----+-------+------+----------+----------+
			 * | 1 | 1 | X'00' | 1 | Variable | 2 |
			 * +----+-----+-------+------+----------+----------+
			 *
			 * Where:
			 *
			 * o VER protocol version: X'05'
			 * o REP Reply field:
			 * o X'00' succeeded
			 * o X'01' general SOCKS server failure
			 * o X'02' connection not allowed by ruleset
			 * o X'03' Network unreachable
			 * o X'04' Host unreachable
			 * o X'05' Connection refused
			 * o X'06' TTL expired
			 * o X'07' Command not supported
			 * o X'08' Address type not supported
			 * o X'09' to X'FF' unassigned
			 * o RSV RESERVED
			 * o ATYP address type of following address
			 * o IP V4 address: X'01'
			 * o DOMAINNAME: X'03'
			 * o IP V6 address: X'04'
			 * o BND.ADDR server bound address
			 * o BND.PORT server bound port in network octet order
			 */

			// in.read(buf, 0, 4);
			ProxySOCKS5.fill(this.in, buf, 4);

			if (buf[1] != 0) {
				try {
					this.socket.close();
				} catch (final Exception eee) {}
				throw new JSchException("ProxySOCKS5: server returns " + buf[1]);
			}

			switch (buf[3] & 0xff) {
				case 1:
					// in.read(buf, 0, 6);
					ProxySOCKS5.fill(this.in, buf, 6);
					break;
				case 3:
					// in.read(buf, 0, 1);
					ProxySOCKS5.fill(this.in, buf, 1);
					// in.read(buf, 0, buf[0]+2);
					ProxySOCKS5.fill(this.in, buf, (buf[0] & 0xff) + 2);
					break;
				case 4:
					// in.read(buf, 0, 18);
					ProxySOCKS5.fill(this.in, buf, 18);
					break;
				default:
			}
		} catch (final RuntimeException e) {
			throw e;
		} catch (final Exception e) {
			try {
				if (this.socket != null) {
					this.socket.close();
				}
			} catch (final Exception eee) {}
			final String message = "ProxySOCKS5: " + e.toString();
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

	private static void fill(final InputStream in, final byte[] buf, final int len) throws JSchException, IOException {
		int s = 0;
		while (s < len) {
			final int i = in.read(buf, s, len - s);
			if (i <= 0) {
				throw new JSchException("ProxySOCKS5: stream is closed");
			}
			s += i;
		}
	}
}
