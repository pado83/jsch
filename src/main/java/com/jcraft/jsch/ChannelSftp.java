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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.Vector;

public class ChannelSftp extends ChannelSession {

	static private final int LOCAL_MAXIMUM_PACKET_SIZE = 32 * 1024;
	static private final int LOCAL_WINDOW_SIZE_MAX = (64 * LOCAL_MAXIMUM_PACKET_SIZE);

	private static final byte SSH_FXP_INIT = 1;
	private static final byte SSH_FXP_VERSION = 2;
	private static final byte SSH_FXP_OPEN = 3;
	private static final byte SSH_FXP_CLOSE = 4;
	private static final byte SSH_FXP_READ = 5;
	private static final byte SSH_FXP_WRITE = 6;
	private static final byte SSH_FXP_LSTAT = 7;
	private static final byte SSH_FXP_FSTAT = 8;
	private static final byte SSH_FXP_SETSTAT = 9;
	private static final byte SSH_FXP_FSETSTAT = 10;
	private static final byte SSH_FXP_OPENDIR = 11;
	private static final byte SSH_FXP_READDIR = 12;
	private static final byte SSH_FXP_REMOVE = 13;
	private static final byte SSH_FXP_MKDIR = 14;
	private static final byte SSH_FXP_RMDIR = 15;
	private static final byte SSH_FXP_REALPATH = 16;
	private static final byte SSH_FXP_STAT = 17;
	private static final byte SSH_FXP_RENAME = 18;
	private static final byte SSH_FXP_READLINK = 19;
	private static final byte SSH_FXP_SYMLINK = 20;
	private static final byte SSH_FXP_STATUS = 101;
	private static final byte SSH_FXP_HANDLE = 102;
	private static final byte SSH_FXP_DATA = 103;
	private static final byte SSH_FXP_NAME = 104;
	private static final byte SSH_FXP_ATTRS = 105;
	private static final byte SSH_FXP_EXTENDED = (byte) 200;
	private static final byte SSH_FXP_EXTENDED_REPLY = (byte) 201;

	// pflags
	private static final int SSH_FXF_READ = 0x00000001;
	private static final int SSH_FXF_WRITE = 0x00000002;
	private static final int SSH_FXF_APPEND = 0x00000004;
	private static final int SSH_FXF_CREAT = 0x00000008;
	private static final int SSH_FXF_TRUNC = 0x00000010;
	private static final int SSH_FXF_EXCL = 0x00000020;

	private static final int SSH_FILEXFER_ATTR_SIZE = 0x00000001;
	private static final int SSH_FILEXFER_ATTR_UIDGID = 0x00000002;
	private static final int SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
	private static final int SSH_FILEXFER_ATTR_ACMODTIME = 0x00000008;
	private static final int SSH_FILEXFER_ATTR_EXTENDED = 0x80000000;

	public static final int SSH_FX_OK = 0;
	public static final int SSH_FX_EOF = 1;
	public static final int SSH_FX_NO_SUCH_FILE = 2;
	public static final int SSH_FX_PERMISSION_DENIED = 3;
	public static final int SSH_FX_FAILURE = 4;
	public static final int SSH_FX_BAD_MESSAGE = 5;
	public static final int SSH_FX_NO_CONNECTION = 6;
	public static final int SSH_FX_CONNECTION_LOST = 7;
	public static final int SSH_FX_OP_UNSUPPORTED = 8;
	/*
	 * SSH_FX_OK
	 * Indicates successful completion of the operation.
	 * SSH_FX_EOF
	 * indicates end-of-file condition; for SSH_FX_READ it means that no
	 * more data is available in the file, and for SSH_FX_READDIR it
	 * indicates that no more files are contained in the directory.
	 * SSH_FX_NO_SUCH_FILE
	 * is returned when a reference is made to a file which should exist
	 * but doesn't.
	 * SSH_FX_PERMISSION_DENIED
	 * is returned when the authenticated user does not have sufficient
	 * permissions to perform the operation.
	 * SSH_FX_FAILURE
	 * is a generic catch-all error message; it should be returned if an
	 * error occurs for which there is no more specific error code
	 * defined.
	 * SSH_FX_BAD_MESSAGE
	 * may be returned if a badly formatted packet or protocol
	 * incompatibility is detected.
	 * SSH_FX_NO_CONNECTION
	 * is a pseudo-error which indicates that the client has no
	 * connection to the server (it can only be generated locally by the
	 * client, and MUST NOT be returned by servers).
	 * SSH_FX_CONNECTION_LOST
	 * is a pseudo-error which indicates that the connection to the
	 * server has been lost (it can only be generated locally by the
	 * client, and MUST NOT be returned by servers).
	 * SSH_FX_OP_UNSUPPORTED
	 * indicates that an attempt was made to perform an operation which
	 * is not supported for the server (it may be generated locally by
	 * the client if e.g. the version number exchange indicates that a
	 * required feature is not supported by the server, or it may be
	 * returned by the server if the server does not implement an
	 * operation).
	 */
	private static final int MAX_MSG_LENGTH = 256 * 1024;

	public static final int OVERWRITE = 0;
	public static final int RESUME = 1;
	public static final int APPEND = 2;

	private final boolean interactive = false;
	private int seq = 1;
	private final int[] ackid = new int[1];

	private Buffer buf;
	private Packet packet;

	// The followings will be used in file uploading.
	private Buffer obuf;
	private Packet opacket;

	private final int client_version = 3;
	private int server_version = 3;
	private final String version = String.valueOf(this.client_version);

	private java.util.Hashtable extensions = null;
	private InputStream io_in = null;

	private boolean extension_posix_rename = false;
	private boolean extension_statvfs = false;
	// private boolean extension_fstatvfs = false;
	private boolean extension_hardlink = false;

	/*
	 * 10. Changes from previous protocol versions
	 * The SSH File Transfer Protocol has changed over time, before it's
	 * standardization. The following is a description of the incompatible
	 * changes between different versions.
	 * 10.1 Changes between versions 3 and 2
	 * o The SSH_FXP_READLINK and SSH_FXP_SYMLINK messages were added.
	 * o The SSH_FXP_EXTENDED and SSH_FXP_EXTENDED_REPLY messages were added.
	 * o The SSH_FXP_STATUS message was changed to include fields `error
	 * message' and `language tag'.
	 * 10.2 Changes between versions 2 and 1
	 * o The SSH_FXP_RENAME message was added.
	 * 10.3 Changes between versions 1 and 0
	 * o Implementation changes, no actual protocol changes.
	 */

	private static final String file_separator = java.io.File.separator;
	private static final char file_separatorc = java.io.File.separatorChar;
	private static boolean fs_is_bs = (byte) java.io.File.separatorChar == '\\';

	private String cwd;
	private String home;
	private String lcwd;

	private static final String UTF8 = "UTF-8";
	private String fEncoding = UTF8;
	private boolean fEncoding_is_utf8 = true;

	private RequestQueue rq = new RequestQueue(16);

	/**
	 * Specify how many requests may be sent at any one time.
	 * Increasing this value may slightly improve file transfer speed but will
	 * increase memory usage. The default is 16 requests.
	 *
	 * @param bulk_requests how many requests may be outstanding at any one time.
	 */
	public void setBulkRequests(final int bulk_requests) throws JSchException {
		if (bulk_requests > 0) {
			this.rq = new RequestQueue(bulk_requests);
		} else {
			throw new JSchException("setBulkRequests: " +
					bulk_requests + " must be greater than 0.");
		}
	}

	/**
	 * This method will return the value how many requests may be
	 * sent at any one time.
	 *
	 * @return how many requests may be sent at any one time.
	 */
	public int getBulkRequests() {
		return this.rq.size();
	}

	public ChannelSftp() {
		super();
		this.setLocalWindowSizeMax(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalWindowSize(LOCAL_WINDOW_SIZE_MAX);
		this.setLocalPacketSize(LOCAL_MAXIMUM_PACKET_SIZE);
	}

	@Override
	void init() {}

	@Override
	public void start() throws JSchException {
		try {

			final PipedOutputStream pos = new PipedOutputStream();
			this.io.setOutputStream(pos);
			final PipedInputStream pis = new MyPipedInputStream(pos, this.rmpsize);
			this.io.setInputStream(pis);

			this.io_in = this.io.in;

			if (this.io_in == null) {
				throw new JSchException("channel is down");
			}

			final Request request = new RequestSftp();
			request.request(this.getSession(), this);

			/*
			 * System.err.println("lmpsize: "+lmpsize);
			 * System.err.println("lwsize: "+lwsize);
			 * System.err.println("rmpsize: "+rmpsize);
			 * System.err.println("rwsize: "+rwsize);
			 */

			this.buf = new Buffer(this.lmpsize);
			this.packet = new Packet(this.buf);

			this.obuf = new Buffer(this.rmpsize);
			this.opacket = new Packet(this.obuf);

			final int i = 0;
			int length;
			int type;
			final byte[] str;

			// send SSH_FXP_INIT
			this.sendINIT();

			// receive SSH_FXP_VERSION
			Header header = new Header();
			header = this.header(this.buf, header);
			length = header.length;
			if (length > MAX_MSG_LENGTH) {
				throw new SftpException(SSH_FX_FAILURE,
						"Received message is too long: " + length);
			}
			type = header.type; // 2 -> SSH_FXP_VERSION
			this.server_version = header.rid;
			// System.err.println("SFTP protocol server-version="+server_version);
			this.extensions = new java.util.Hashtable();
			if (length > 0) {
				// extension data
				this.fill(this.buf, length);
				byte[] extension_name = null;
				byte[] extension_data = null;
				while (length > 0) {
					extension_name = this.buf.getString();
					length -= (4 + extension_name.length);
					extension_data = this.buf.getString();
					length -= (4 + extension_data.length);
					this.extensions.put(Util.byte2str(extension_name),
							Util.byte2str(extension_data));
				}
			}

			if (this.extensions.get("posix-rename@openssh.com") != null &&
					this.extensions.get("posix-rename@openssh.com").equals("1")) {
				this.extension_posix_rename = true;
			}

			if (this.extensions.get("statvfs@openssh.com") != null &&
					this.extensions.get("statvfs@openssh.com").equals("2")) {
				this.extension_statvfs = true;
			}

			/*
			 * if(extensions.get("fstatvfs@openssh.com")!=null &&
			 * extensions.get("fstatvfs@openssh.com").equals("2")){
			 * extension_fstatvfs = true;
			 * }
			 */

			if (this.extensions.get("hardlink@openssh.com") != null &&
					this.extensions.get("hardlink@openssh.com").equals("1")) {
				this.extension_hardlink = true;
			}

			this.lcwd = new File(".").getCanonicalPath();
		} catch (final Exception e) {
			// System.err.println(e);
			if (e instanceof JSchException) {
				throw (JSchException) e;
			}
			if (e instanceof Throwable) {
				throw new JSchException(e.toString(), e);
			}
			throw new JSchException(e.toString());
		}
	}

	public void quit() {
		this.disconnect();
	}

	public void exit() {
		this.disconnect();
	}

	public void lcd(String path) throws SftpException {
		path = this.localAbsolutePath(path);
		if ((new File(path)).isDirectory()) {
			try {
				path = (new File(path)).getCanonicalPath();
			} catch (final Exception e) {}
			this.lcwd = path;
			return;
		}
		throw new SftpException(SSH_FX_NO_SUCH_FILE, "No such directory");
	}

	public void cd(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);
			path = this.isUnique(path);

			final byte[] str = this._realpath(path);
			final SftpATTRS attr = this._stat(str);

			if ((attr.getFlags() & SftpATTRS.SSH_FILEXFER_ATTR_PERMISSIONS) == 0) {
				throw new SftpException(SSH_FX_FAILURE,
						"Can't change directory: " + path);
			}
			if (!attr.isDir()) {
				throw new SftpException(SSH_FX_FAILURE,
						"Can't change directory: " + path);
			}

			this.setCwd(Util.byte2str(str, this.fEncoding));
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void put(final String src, final String dst) throws SftpException {
		this.put(src, dst, null, OVERWRITE);
	}

	public void put(final String src, final String dst, final int mode) throws SftpException {
		this.put(src, dst, null, mode);
	}

	public void put(final String src, final String dst,
			final SftpProgressMonitor monitor) throws SftpException {
		this.put(src, dst, monitor, OVERWRITE);
	}

	/**
	 * Sends data from <code>src</code> file to <code>dst</code> file.
	 * The <code>mode</code> should be <code>OVERWRITE</code>,
	 * <code>RESUME</code> or <code>APPEND</code>.
	 *
	 * @param src source file
	 * @param dst destination file
	 * @param monitor progress monitor
	 * @param mode how data should be added to dst
	 */
	public void put(String src, String dst,
			final SftpProgressMonitor monitor, final int mode) throws SftpException {

		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			src = this.localAbsolutePath(src);
			dst = this.remoteAbsolutePath(dst);

			Vector v = this.glob_remote(dst);
			int vsize = v.size();
			if (vsize != 1) {
				if (vsize == 0) {
					if (this.isPattern(dst)) {
						throw new SftpException(SSH_FX_FAILURE, dst);
					} else {
						dst = Util.unquote(dst);
					}
				}
				throw new SftpException(SSH_FX_FAILURE, v.toString());
			} else {
				dst = (String) (v.elementAt(0));
			}

			final boolean isRemoteDir = this.isRemoteDir(dst);

			v = this.glob_local(src);
			vsize = v.size();

			StringBuffer dstsb = null;
			if (isRemoteDir) {
				if (!dst.endsWith("/")) {
					dst += "/";
				}
				dstsb = new StringBuffer(dst);
			} else if (vsize > 1) {
				throw new SftpException(SSH_FX_FAILURE,
						"Copying multiple files, but the destination is missing or a file.");
			}

			for (int j = 0; j < vsize; j++) {
				final String _src = (String) (v.elementAt(j));
				String _dst = null;
				if (isRemoteDir) {
					int i = _src.lastIndexOf(file_separatorc);
					if (fs_is_bs) {
						final int ii = _src.lastIndexOf('/');
						if (ii != -1 && ii > i) {
							i = ii;
						}
					}
					if (i == -1) {
						dstsb.append(_src);
					} else {
						dstsb.append(_src.substring(i + 1));
					}
					_dst = dstsb.toString();
					dstsb.delete(dst.length(), _dst.length());
				} else {
					_dst = dst;
				}
				// System.err.println("_dst "+_dst);

				long size_of_dst = 0;
				if (mode == RESUME) {
					try {
						final SftpATTRS attr = this._stat(_dst);
						size_of_dst = attr.getSize();
					} catch (final Exception eee) {
						// System.err.println(eee);
					}
					final long size_of_src = new File(_src).length();
					if (size_of_src < size_of_dst) {
						throw new SftpException(SSH_FX_FAILURE,
								"failed to resume for " + _dst);
					}
					if (size_of_src == size_of_dst) {
						return;
					}
				}

				if (monitor != null) {
					monitor.init(SftpProgressMonitor.PUT, _src, _dst,
							(new File(_src)).length());
					if (mode == RESUME) {
						monitor.count(size_of_dst);
					}
				}
				FileInputStream fis = null;
				try {
					fis = new FileInputStream(_src);
					this._put(fis, _dst, monitor, mode);
				} finally {
					if (fis != null) {
						fis.close();
					}
				}
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, e.toString(), e);
			}
			throw new SftpException(SSH_FX_FAILURE, e.toString());
		}
	}

	public void put(final InputStream src, final String dst) throws SftpException {
		this.put(src, dst, null, OVERWRITE);
	}

	public void put(final InputStream src, final String dst, final int mode) throws SftpException {
		this.put(src, dst, null, mode);
	}

	public void put(final InputStream src, final String dst,
			final SftpProgressMonitor monitor) throws SftpException {
		this.put(src, dst, monitor, OVERWRITE);
	}

	/**
	 * Sends data from the input stream <code>src</code> to <code>dst</code> file.
	 * The <code>mode</code> should be <code>OVERWRITE</code>,
	 * <code>RESUME</code> or <code>APPEND</code>.
	 *
	 * @param src input stream
	 * @param dst destination file
	 * @param monitor progress monitor
	 * @param mode how data should be added to dst
	 */
	public void put(final InputStream src, String dst,
			final SftpProgressMonitor monitor, final int mode) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			dst = this.remoteAbsolutePath(dst);

			final Vector v = this.glob_remote(dst);
			final int vsize = v.size();
			if (vsize != 1) {
				if (vsize == 0) {
					if (this.isPattern(dst)) {
						throw new SftpException(SSH_FX_FAILURE, dst);
					} else {
						dst = Util.unquote(dst);
					}
				}
				throw new SftpException(SSH_FX_FAILURE, v.toString());
			} else {
				dst = (String) (v.elementAt(0));
			}

			if (monitor != null) {
				monitor.init(SftpProgressMonitor.PUT,
						"-", dst,
						SftpProgressMonitor.UNKNOWN_SIZE);
			}

			this._put(src, dst, monitor, mode);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				if (((SftpException) e).id == SSH_FX_FAILURE &&
						this.isRemoteDir(dst)) {
					throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
				}
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, e.toString(), e);
			}
			throw new SftpException(SSH_FX_FAILURE, e.toString());
		}
	}

	public void _put(final InputStream src, final String dst,
			final SftpProgressMonitor monitor, final int mode) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			final byte[] dstb = Util.str2byte(dst, this.fEncoding);
			long skip = 0;
			if (mode == RESUME || mode == APPEND) {
				try {
					final SftpATTRS attr = this._stat(dstb);
					skip = attr.getSize();
				} catch (final Exception eee) {
					// System.err.println(eee);
				}
			}
			if (mode == RESUME && skip > 0) {
				final long skipped = src.skip(skip);
				if (skipped < skip) {
					throw new SftpException(SSH_FX_FAILURE, "failed to resume for " + dst);
				}
			}

			if (mode == OVERWRITE) {
				this.sendOPENW(dstb);
			} else {
				this.sendOPENA(dstb);
			}

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
				throw new SftpException(SSH_FX_FAILURE, "invalid type=" + type);
			}
			if (type == SSH_FXP_STATUS) {
				final int i = this.buf.getInt();
				this.throwStatusError(this.buf, i);
			}
			final byte[] handle = this.buf.getString(); // handle
			byte[] data = null;

			final boolean dontcopy = true;

			if (!dontcopy) { // This case will not work anymore.
				data = new byte[this.obuf.buffer.length
						- (5 + 13 + 21 + handle.length + Session.buffer_margin)];
			}

			long offset = 0;
			if (mode == RESUME || mode == APPEND) {
				offset += skip;
			}

			final int startid = this.seq;
			int ackcount = 0;
			int _s = 0;
			int _datalen = 0;

			if (!dontcopy) { // This case will not work anymore.
				_datalen = data.length;
			} else {
				data = this.obuf.buffer;
				_s = 5 + 13 + 21 + handle.length;
				_datalen = this.obuf.buffer.length - _s - Session.buffer_margin;
			}

			final int bulk_requests = this.rq.size();

			while (true) {
				int nread = 0;
				int count = 0;
				int s = _s;
				int datalen = _datalen;

				do {
					nread = src.read(data, s, datalen);
					if (nread > 0) {
						s += nread;
						datalen -= nread;
						count += nread;
					}
				} while (datalen > 0 && nread > 0);
				if (count <= 0) {
					break;
				}

				int foo = count;
				while (foo > 0) {
					if ((this.seq - 1) == startid ||
							((this.seq - startid) - ackcount) >= bulk_requests) {
						while (((this.seq - startid) - ackcount) >= bulk_requests) {
							if (this.checkStatus(this.ackid, header)) {
								final int _ackid = this.ackid[0];
								if (startid > _ackid || _ackid > this.seq - 1) {
									if (_ackid == this.seq) {
										System.err.println("ack error: startid=" + startid + " seq=" + this.seq + " _ackid=" + _ackid);
									} else {
										throw new SftpException(SSH_FX_FAILURE, "ack error: startid=" + startid + " seq=" + this.seq + " _ackid=" + _ackid);
									}
								}
								ackcount++;
							} else {
								break;
							}
						}
					}
					if (dontcopy) {
						foo -= this.sendWRITE(handle, offset, data, 0, foo);
						if (data != this.obuf.buffer) {
							data = this.obuf.buffer;
							_datalen = this.obuf.buffer.length - _s - Session.buffer_margin;
						}
					} else {
						foo -= this.sendWRITE(handle, offset, data, _s, foo);
					}
				}
				offset += count;
				if (monitor != null && !monitor.count(count)) {
					break;
				}
			}
			final int _ackcount = this.seq - startid;
			while (_ackcount > ackcount) {
				if (!this.checkStatus(null, header)) {
					break;
				}
				ackcount++;
			}
			if (monitor != null) {
				monitor.end();
			}
			this._sendCLOSE(handle, header);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, e.toString(), e);
			}
			throw new SftpException(SSH_FX_FAILURE, e.toString());
		}
	}

	public OutputStream put(final String dst) throws SftpException {
		return this.put(dst, (SftpProgressMonitor) null, OVERWRITE);
	}

	public OutputStream put(final String dst, final int mode) throws SftpException {
		return this.put(dst, (SftpProgressMonitor) null, mode);
	}

	public OutputStream put(final String dst, final SftpProgressMonitor monitor, final int mode) throws SftpException {
		return this.put(dst, monitor, mode, 0);
	}

	/**
	 * Sends data from the output stream to <code>dst</code> file.
	 * The <code>mode</code> should be <code>OVERWRITE</code>,
	 * <code>RESUME</code> or <code>APPEND</code>.
	 *
	 * @param dst destination file
	 * @param monitor progress monitor
	 * @param mode how data should be added to dst
	 * @param offset data will be added at offset
	 * @return output stream, which accepts data to be transferred.
	 */
	public OutputStream put(String dst, final SftpProgressMonitor monitor, final int mode, long offset) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			dst = this.remoteAbsolutePath(dst);
			dst = this.isUnique(dst);

			if (this.isRemoteDir(dst)) {
				throw new SftpException(SSH_FX_FAILURE, dst + " is a directory");
			}

			final byte[] dstb = Util.str2byte(dst, this.fEncoding);

			long skip = 0;
			if (mode == RESUME || mode == APPEND) {
				try {
					final SftpATTRS attr = this._stat(dstb);
					skip = attr.getSize();
				} catch (final Exception eee) {
					// System.err.println(eee);
				}
			}

			if (monitor != null) {
				monitor.init(SftpProgressMonitor.PUT,
						"-", dst,
						SftpProgressMonitor.UNKNOWN_SIZE);
			}

			if (mode == OVERWRITE) {
				this.sendOPENW(dstb);
			} else {
				this.sendOPENA(dstb);
			}

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			if (type == SSH_FXP_STATUS) {
				final int i = this.buf.getInt();
				this.throwStatusError(this.buf, i);
			}
			final byte[] handle = this.buf.getString(); // handle

			if (mode == RESUME || mode == APPEND) {
				offset += skip;
			}

			final long[] _offset = new long[1];
			_offset[0] = offset;
			final OutputStream out = new OutputStream() {

				private boolean init = true;
				private boolean isClosed = false;
				private final int[] ackid = new int[1];
				private int startid = 0;
				private int _ackid = 0;
				private int ackcount = 0;
				private int writecount = 0;
				private final Header header = new Header();

				@Override
				public void write(final byte[] d) throws java.io.IOException {
					this.write(d, 0, d.length);
				}

				@Override
				public void write(final byte[] d, int s, final int len) throws java.io.IOException {
					if (this.init) {
						this.startid = ChannelSftp.this.seq;
						this._ackid = ChannelSftp.this.seq;
						this.init = false;
					}

					if (this.isClosed) {
						throw new IOException("stream already closed");
					}

					try {
						int _len = len;
						while (_len > 0) {
							final int sent = ChannelSftp.this.sendWRITE(handle, _offset[0], d, s, _len);
							this.writecount++;
							_offset[0] += sent;
							s += sent;
							_len -= sent;
							if ((ChannelSftp.this.seq - 1) == this.startid ||
									ChannelSftp.this.io_in.available() >= 1024) {
								while (ChannelSftp.this.io_in.available() > 0) {
									if (ChannelSftp.this.checkStatus(this.ackid, this.header)) {
										this._ackid = this.ackid[0];
										if (this.startid > this._ackid || this._ackid > ChannelSftp.this.seq - 1) {
											throw new SftpException(SSH_FX_FAILURE, "");
										}
										this.ackcount++;
									} else {
										break;
									}
								}
							}
						}
						if (monitor != null && !monitor.count(len)) {
							this.close();
							throw new IOException("canceled");
						}
					} catch (final IOException e) {
						throw e;
					} catch (final Exception e) {
						throw new IOException(e.toString());
					}
				}

				byte[] _data = new byte[1];

				@Override
				public void write(final int foo) throws java.io.IOException {
					this._data[0] = (byte) foo;
					this.write(this._data, 0, 1);
				}

				@Override
				public void flush() throws java.io.IOException {

					if (this.isClosed) {
						throw new IOException("stream already closed");
					}

					if (!this.init) {
						try {
							while (this.writecount > this.ackcount) {
								if (!ChannelSftp.this.checkStatus(null, this.header)) {
									break;
								}
								this.ackcount++;
							}
						} catch (final SftpException e) {
							throw new IOException(e.toString());
						}
					}
				}

				@Override
				public void close() throws java.io.IOException {
					if (this.isClosed) {
						return;
					}
					this.flush();
					if (monitor != null) {
						monitor.end();
					}
					try {
						ChannelSftp.this._sendCLOSE(handle, this.header);
					} catch (final IOException e) {
						throw e;
					} catch (final Exception e) {
						throw new IOException(e.toString());
					}
					this.isClosed = true;
				}
			};
			return out;
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void get(final String src, final String dst) throws SftpException {
		this.get(src, dst, null, OVERWRITE);
	}

	public void get(final String src, final String dst,
			final SftpProgressMonitor monitor) throws SftpException {
		this.get(src, dst, monitor, OVERWRITE);
	}

	public void get(String src, String dst,
			final SftpProgressMonitor monitor, final int mode) throws SftpException {
		// System.out.println("get: "+src+" "+dst);

		boolean _dstExist = false;
		String _dst = null;
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			src = this.remoteAbsolutePath(src);
			dst = this.localAbsolutePath(dst);

			final Vector v = this.glob_remote(src);
			final int vsize = v.size();
			if (vsize == 0) {
				throw new SftpException(SSH_FX_NO_SUCH_FILE, "No such file");
			}

			final File dstFile = new File(dst);
			final boolean isDstDir = dstFile.isDirectory();
			StringBuffer dstsb = null;
			if (isDstDir) {
				if (!dst.endsWith(file_separator)) {
					dst += file_separator;
				}
				dstsb = new StringBuffer(dst);
			} else if (vsize > 1) {
				throw new SftpException(SSH_FX_FAILURE,
						"Copying multiple files, but destination is missing or a file.");
			}

			for (int j = 0; j < vsize; j++) {
				final String _src = (String) (v.elementAt(j));
				final SftpATTRS attr = this._stat(_src);
				if (attr.isDir()) {
					throw new SftpException(SSH_FX_FAILURE,
							"not supported to get directory " + _src);
				}

				_dst = null;
				if (isDstDir) {
					final int i = _src.lastIndexOf('/');
					if (i == -1) {
						dstsb.append(_src);
					} else {
						dstsb.append(_src.substring(i + 1));
					}
					_dst = dstsb.toString();
					if (_dst.indexOf("..") != -1) {
						final String dstc = (new java.io.File(dst)).getCanonicalPath();
						final String _dstc = (new java.io.File(_dst)).getCanonicalPath();
						if (!(_dstc.length() > dstc.length() &&
								_dstc.substring(0, dstc.length() + 1).equals(dstc + file_separator))) {
							throw new SftpException(SSH_FX_FAILURE,
									"writing to an unexpected file " + _src);
						}
					}
					dstsb.delete(dst.length(), _dst.length());
				} else {
					_dst = dst;
				}

				final File _dstFile = new File(_dst);
				if (mode == RESUME) {
					final long size_of_src = attr.getSize();
					final long size_of_dst = _dstFile.length();
					if (size_of_dst > size_of_src) {
						throw new SftpException(SSH_FX_FAILURE,
								"failed to resume for " + _dst);
					}
					if (size_of_dst == size_of_src) {
						return;
					}
				}

				if (monitor != null) {
					monitor.init(SftpProgressMonitor.GET, _src, _dst, attr.getSize());
					if (mode == RESUME) {
						monitor.count(_dstFile.length());
					}
				}

				FileOutputStream fos = null;
				_dstExist = _dstFile.exists();
				try {
					if (mode == OVERWRITE) {
						fos = new FileOutputStream(_dst);
					} else {
						fos = new FileOutputStream(_dst, true); // append
					}
					// System.err.println("_get: "+_src+", "+_dst);
					this._get(_src, fos, monitor, mode, new File(_dst).length());
				} finally {
					if (fos != null) {
						fos.close();
					}
				}
			}
		} catch (final Exception e) {
			if (!_dstExist && _dst != null) {
				final File _dstFile = new File(_dst);
				if (_dstFile.exists() && _dstFile.length() == 0) {
					_dstFile.delete();
				}
			}
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void get(final String src, final OutputStream dst) throws SftpException {
		this.get(src, dst, null, OVERWRITE, 0);
	}

	public void get(final String src, final OutputStream dst,
			final SftpProgressMonitor monitor) throws SftpException {
		this.get(src, dst, monitor, OVERWRITE, 0);
	}

	public void get(String src, final OutputStream dst,
			final SftpProgressMonitor monitor, final int mode, final long skip) throws SftpException {
		// System.err.println("get: "+src+", "+dst);
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			src = this.remoteAbsolutePath(src);
			src = this.isUnique(src);

			if (monitor != null) {
				final SftpATTRS attr = this._stat(src);
				monitor.init(SftpProgressMonitor.GET, src, "??", attr.getSize());
				if (mode == RESUME) {
					monitor.count(skip);
				}
			}
			this._get(src, dst, monitor, mode, skip);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private void _get(final String src, final OutputStream dst,
			final SftpProgressMonitor monitor, final int mode, final long skip) throws SftpException {
		// System.err.println("_get: "+src+", "+dst);

		final byte[] srcb = Util.str2byte(src, this.fEncoding);
		try {
			this.sendOPENR(srcb);

			Header header = new Header();
			header = this.header(this.buf, header);
			int length = header.length;
			int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}

			if (type == SSH_FXP_STATUS) {
				final int i = this.buf.getInt();
				this.throwStatusError(this.buf, i);
			}

			final byte[] handle = this.buf.getString(); // filename

			long offset = 0;
			if (mode == RESUME) {
				offset += skip;
			}

			int request_max = 1;
			this.rq.init();
			long request_offset = offset;

			int request_len = this.buf.buffer.length - 13;
			if (this.server_version == 0) {
				request_len = 1024;
			}

			loop: while (true) {

				while (this.rq.count() < request_max) {
					this.sendREAD(handle, request_offset, request_len, this.rq);
					request_offset += request_len;
				}

				header = this.header(this.buf, header);
				length = header.length;
				type = header.type;

				RequestQueue.Request rr = null;
				try {
					rr = this.rq.get(header.rid);
				} catch (final RequestQueue.OutOfOrderException e) {
					request_offset = e.offset;
					this.skip(header.length);
					this.rq.cancel(header, this.buf);
					continue;
				}

				if (type == SSH_FXP_STATUS) {
					this.fill(this.buf, length);
					final int i = this.buf.getInt();
					if (i == SSH_FX_EOF) {
						break loop;
					}
					this.throwStatusError(this.buf, i);
				}

				if (type != SSH_FXP_DATA) {
					break loop;
				}

				this.buf.rewind();
				this.fill(this.buf.buffer, 0, 4);
				length -= 4;
				final int length_of_data = this.buf.getInt(); // length of data

				/**
				 * Since sftp protocol version 6, "end-of-file" has been defined,
				 * 
				 * byte SSH_FXP_DATA
				 * uint32 request-id
				 * string data
				 * bool end-of-file [optional]
				 * 
				 * but some sftpd server will send such a field in the sftp protocol 3 ;-(
				 */
				final int optional_data = length - length_of_data;

				int foo = length_of_data;
				while (foo > 0) {
					int bar = foo;
					if (bar > this.buf.buffer.length) {
						bar = this.buf.buffer.length;
					}
					final int data_len = this.io_in.read(this.buf.buffer, 0, bar);
					if (data_len < 0) {
						break loop;
					}

					dst.write(this.buf.buffer, 0, data_len);

					offset += data_len;
					foo -= data_len;

					if (monitor != null) {
						if (!monitor.count(data_len)) {
							this.skip(foo);
							if (optional_data > 0) {
								this.skip(optional_data);
							}
							break loop;
						}
					}

				}
				// System.err.println("length: "+length); // length should be 0

				if (optional_data > 0) {
					this.skip(optional_data);
				}

				if (length_of_data < rr.length) { //
					this.rq.cancel(header, this.buf);
					this.sendREAD(handle, rr.offset + length_of_data, (int) (rr.length - length_of_data), this.rq);
					request_offset = rr.offset + rr.length;
				}

				if (request_max < this.rq.size()) {
					request_max++;
				}
			}
			dst.flush();

			if (monitor != null) {
				monitor.end();
			}

			this.rq.cancel(header, this.buf);

			this._sendCLOSE(handle, header);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private class RequestQueue {

		class OutOfOrderException extends Exception {

			/**
			 * 
			 */
			private static final long serialVersionUID = -6383550604258021026L;
			long offset;

			OutOfOrderException(final long offset) {
				this.offset = offset;
			}
		}

		class Request {

			int id;
			long offset;
			long length;
		}

		Request[] rrq = null;
		int head, count;

		RequestQueue(final int size) {
			this.rrq = new Request[size];
			for (int i = 0; i < this.rrq.length; i++) {
				this.rrq[i] = new Request();
			}
			this.init();
		}

		void init() {
			this.head = this.count = 0;
		}

		void add(final int id, final long offset, final int length) {
			if (this.count == 0) {
				this.head = 0;
			}
			int tail = this.head + this.count;
			if (tail >= this.rrq.length) {
				tail -= this.rrq.length;
			}
			this.rrq[tail].id = id;
			this.rrq[tail].offset = offset;
			this.rrq[tail].length = length;
			this.count++;
		}

		Request get(final int id) throws OutOfOrderException, SftpException {
			this.count -= 1;
			final int i = this.head;
			this.head++;
			if (this.head == this.rrq.length) {
				this.head = 0;
			}
			if (this.rrq[i].id != id) {
				final long offset = this.getOffset();
				boolean find = false;
				for (int j = 0; j < this.rrq.length; j++) {
					if (this.rrq[j].id == id) {
						find = true;
						this.rrq[j].id = 0;
						break;
					}
				}
				if (find) {
					throw new OutOfOrderException(offset);
				}
				throw new SftpException(SSH_FX_FAILURE,
						"RequestQueue: unknown request id " + id);
			}
			this.rrq[i].id = 0;
			return this.rrq[i];
		}

		int count() {
			return this.count;
		}

		int size() {
			return this.rrq.length;
		}

		void cancel(Header header, final Buffer buf) throws IOException {
			final int _count = this.count;
			for (int i = 0; i < _count; i++) {
				header = ChannelSftp.this.header(buf, header);
				final int length = header.length;
				for (int j = 0; j < this.rrq.length; j++) {
					if (this.rrq[j].id == header.rid) {
						this.rrq[j].id = 0;
						break;
					}
				}
				ChannelSftp.this.skip(length);
			}
			this.init();
		}

		long getOffset() {
			long result = Long.MAX_VALUE;

			for (int i = 0; i < this.rrq.length; i++) {
				if (this.rrq[i].id == 0) {
					continue;
				}
				if (result > this.rrq[i].offset) {
					result = this.rrq[i].offset;
				}
			}

			return result;
		}
	}

	public InputStream get(final String src) throws SftpException {
		return this.get(src, null, 0L);
	}

	public InputStream get(final String src, final SftpProgressMonitor monitor) throws SftpException {
		return this.get(src, monitor, 0L);
	}

	/**
	 * @deprecated This method will be deleted in the future.
	 */
	@Deprecated
	public InputStream get(final String src, final int mode) throws SftpException {
		return this.get(src, null, 0L);
	}

	/**
	 * @deprecated This method will be deleted in the future.
	 */
	@Deprecated
	public InputStream get(final String src, final SftpProgressMonitor monitor, final int mode) throws SftpException {
		return this.get(src, monitor, 0L);
	}

	public InputStream get(String src, final SftpProgressMonitor monitor, final long skip) throws SftpException {

		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			src = this.remoteAbsolutePath(src);
			src = this.isUnique(src);

			final byte[] srcb = Util.str2byte(src, this.fEncoding);

			final SftpATTRS attr = this._stat(srcb);
			if (monitor != null) {
				monitor.init(SftpProgressMonitor.GET, src, "??", attr.getSize());
			}

			this.sendOPENR(srcb);

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			if (type == SSH_FXP_STATUS) {
				final int i = this.buf.getInt();
				this.throwStatusError(this.buf, i);
			}

			final byte[] handle = this.buf.getString(); // handle

			this.rq.init();

			final java.io.InputStream in = new java.io.InputStream() {

				long offset = skip;
				boolean closed = false;
				int rest_length = 0;
				byte[] _data = new byte[1];
				byte[] rest_byte = new byte[1024];
				Header header = new Header();
				int request_max = 1;
				long request_offset = this.offset;

				@Override
				public int read() throws java.io.IOException {
					if (this.closed) {
						return -1;
					}
					final int i = this.read(this._data, 0, 1);
					if (i == -1) {
						return -1;
					} else {
						return this._data[0] & 0xff;
					}
				}

				@Override
				public int read(final byte[] d) throws java.io.IOException {
					if (this.closed) {
						return -1;
					}
					return this.read(d, 0, d.length);
				}

				@Override
				public int read(final byte[] d, final int s, int len) throws java.io.IOException {
					if (this.closed) {
						return -1;
					}
					if (d == null) {
						throw new NullPointerException();
					}
					if (s < 0 || len < 0 || s + len > d.length) {
						throw new IndexOutOfBoundsException();
					}
					if (len == 0) {
						return 0;
					}

					if (this.rest_length > 0) {
						int foo = this.rest_length;
						if (foo > len) {
							foo = len;
						}
						System.arraycopy(this.rest_byte, 0, d, s, foo);
						if (foo != this.rest_length) {
							System.arraycopy(this.rest_byte, foo,
									this.rest_byte, 0, this.rest_length - foo);
						}

						if (monitor != null) {
							if (!monitor.count(foo)) {
								this.close();
								return -1;
							}
						}

						this.rest_length -= foo;
						return foo;
					}

					if (ChannelSftp.this.buf.buffer.length - 13 < len) {
						len = ChannelSftp.this.buf.buffer.length - 13;
					}
					if (ChannelSftp.this.server_version == 0 && len > 1024) {
						len = 1024;
					}

					if (ChannelSftp.this.rq.count() == 0
							|| true // working around slow transfer speed for
									// some sftp servers including Titan FTP.
					) {
						int request_len = ChannelSftp.this.buf.buffer.length - 13;
						if (ChannelSftp.this.server_version == 0) {
							request_len = 1024;
						}

						while (ChannelSftp.this.rq.count() < this.request_max) {
							try {
								ChannelSftp.this.sendREAD(handle, this.request_offset, request_len, ChannelSftp.this.rq);
							} catch (final Exception e) {
								throw new IOException("error");
							}
							this.request_offset += request_len;
						}
					}

					this.header = ChannelSftp.this.header(ChannelSftp.this.buf, this.header);
					this.rest_length = this.header.length;
					final int type = this.header.type;
					final int id = this.header.rid;

					RequestQueue.Request rr = null;
					try {
						rr = ChannelSftp.this.rq.get(this.header.rid);
					} catch (final RequestQueue.OutOfOrderException e) {
						this.request_offset = e.offset;
						this.skip(this.header.length);
						ChannelSftp.this.rq.cancel(this.header, ChannelSftp.this.buf);
						return 0;
					} catch (final SftpException e) {
						throw new IOException("error: " + e.toString());
					}

					if (type != SSH_FXP_STATUS && type != SSH_FXP_DATA) {
						throw new IOException("error");
					}
					if (type == SSH_FXP_STATUS) {
						ChannelSftp.this.fill(ChannelSftp.this.buf, this.rest_length);
						final int i = ChannelSftp.this.buf.getInt();
						this.rest_length = 0;
						if (i == SSH_FX_EOF) {
							this.close();
							return -1;
						}
						// throwStatusError(buf, i);
						throw new IOException("error");
					}

					ChannelSftp.this.buf.rewind();
					ChannelSftp.this.fill(ChannelSftp.this.buf.buffer, 0, 4);
					final int length_of_data = ChannelSftp.this.buf.getInt();
					this.rest_length -= 4;

					/**
					 * Since sftp protocol version 6, "end-of-file" has been defined,
					 * 
					 * byte SSH_FXP_DATA
					 * uint32 request-id
					 * string data
					 * bool end-of-file [optional]
					 * 
					 * but some sftpd server will send such a field in the sftp protocol 3 ;-(
					 */
					final int optional_data = this.rest_length - length_of_data;

					this.offset += length_of_data;
					int foo = length_of_data;
					if (foo > 0) {
						int bar = foo;
						if (bar > len) {
							bar = len;
						}
						final int i = ChannelSftp.this.io_in.read(d, s, bar);
						if (i < 0) {
							return -1;
						}
						foo -= i;
						this.rest_length = foo;

						if (foo > 0) {
							if (this.rest_byte.length < foo) {
								this.rest_byte = new byte[foo];
							}
							int _s = 0;
							int _len = foo;
							int j;
							while (_len > 0) {
								j = ChannelSftp.this.io_in.read(this.rest_byte, _s, _len);
								if (j <= 0) {
									break;
								}
								_s += j;
								_len -= j;
							}
						}

						if (optional_data > 0) {
							ChannelSftp.this.io_in.skip(optional_data);
						}

						if (length_of_data < rr.length) { //
							ChannelSftp.this.rq.cancel(this.header, ChannelSftp.this.buf);
							try {
								ChannelSftp.this.sendREAD(handle,
										rr.offset + length_of_data,
										(int) (rr.length - length_of_data), ChannelSftp.this.rq);
							} catch (final Exception e) {
								throw new IOException("error");
							}
							this.request_offset = rr.offset + rr.length;
						}

						if (this.request_max < ChannelSftp.this.rq.size()) {
							this.request_max++;
						}

						if (monitor != null) {
							if (!monitor.count(i)) {
								this.close();
								return -1;
							}
						}

						return i;
					}
					return 0; // ??
				}

				@Override
				public void close() throws IOException {
					if (this.closed) {
						return;
					}
					this.closed = true;
					if (monitor != null) {
						monitor.end();
					}
					ChannelSftp.this.rq.cancel(this.header, ChannelSftp.this.buf);
					try {
						ChannelSftp.this._sendCLOSE(handle, this.header);
					} catch (final Exception e) {
						throw new IOException("error");
					}
				}
			};
			return in;
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public java.util.Vector ls(final String path) throws SftpException {
		final java.util.Vector v = new Vector();
		final LsEntrySelector selector = new LsEntrySelector() {

			@Override
			public int select(final LsEntry entry) {
				v.addElement(entry);
				return CONTINUE;
			}
		};
		this.ls(path, selector);
		return v;
	}

	/**
	 * List files specified by the remote <code>path</code>.
	 * Each files and directories will be passed to
	 * <code>LsEntrySelector#select(LsEntry)</code> method, and if that method
	 * returns <code>LsEntrySelector#BREAK</code>, the operation will be
	 * canceled immediately.
	 *
	 * @see ChannelSftp.LsEntrySelector
	 * @since 0.1.47
	 */
	public void ls(String path, final LsEntrySelector selector) throws SftpException {
		// System.out.println("ls: "+path);
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);
			byte[] pattern = null;
			final java.util.Vector v = new java.util.Vector();

			final int foo = path.lastIndexOf('/');
			String dir = path.substring(0, ((foo == 0) ? 1 : foo));
			String _pattern = path.substring(foo + 1);
			dir = Util.unquote(dir);

			// If pattern has included '*' or '?', we need to convert
			// to UTF-8 string before globbing.
			final byte[][] _pattern_utf8 = new byte[1][];
			final boolean pattern_has_wildcard = this.isPattern(_pattern, _pattern_utf8);

			if (pattern_has_wildcard) {
				pattern = _pattern_utf8[0];
			} else {
				final String upath = Util.unquote(path);
				// SftpATTRS attr=_lstat(upath);
				final SftpATTRS attr = this._stat(upath);
				if (attr.isDir()) {
					pattern = null;
					dir = upath;
				} else {
					/*
					 * // If we can generage longname by ourself,
					 * // we don't have to use openDIR.
					 * String filename=Util.unquote(_pattern);
					 * String longname=...
					 * v.addElement(new LsEntry(filename, longname, attr));
					 * return v;
					 */

					if (this.fEncoding_is_utf8) {
						pattern = _pattern_utf8[0];
						pattern = Util.unquote(pattern);
					} else {
						_pattern = Util.unquote(_pattern);
						pattern = Util.str2byte(_pattern, this.fEncoding);
					}

				}
			}

			this.sendOPENDIR(Util.str2byte(dir, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			int length = header.length;
			int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			if (type == SSH_FXP_STATUS) {
				final int i = this.buf.getInt();
				this.throwStatusError(this.buf, i);
			}

			int cancel = LsEntrySelector.CONTINUE;
			final byte[] handle = this.buf.getString(); // handle

			while (cancel == LsEntrySelector.CONTINUE) {

				this.sendREADDIR(handle);

				header = this.header(this.buf, header);
				length = header.length;
				type = header.type;
				if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME) {
					throw new SftpException(SSH_FX_FAILURE, "");
				}
				if (type == SSH_FXP_STATUS) {
					this.fill(this.buf, length);
					final int i = this.buf.getInt();
					if (i == SSH_FX_EOF) {
						break;
					}
					this.throwStatusError(this.buf, i);
				}

				this.buf.rewind();
				this.fill(this.buf.buffer, 0, 4);
				length -= 4;
				int count = this.buf.getInt();

				final byte[] str;
				final int flags;

				this.buf.reset();
				while (count > 0) {
					if (length > 0) {
						this.buf.shift();
						final int j = (this.buf.buffer.length > (this.buf.index + length)) ? length : (this.buf.buffer.length - this.buf.index);
						final int i = this.fill(this.buf.buffer, this.buf.index, j);
						this.buf.index += i;
						length -= i;
					}
					final byte[] filename = this.buf.getString();
					byte[] longname = null;
					if (this.server_version <= 3) {
						longname = this.buf.getString();
					}
					final SftpATTRS attrs = SftpATTRS.getATTR(this.buf);

					if (cancel == LsEntrySelector.BREAK) {
						count--;
						continue;
					}

					boolean find = false;
					String f = null;
					if (pattern == null) {
						find = true;
					} else if (!pattern_has_wildcard) {
						find = Util.array_equals(pattern, filename);
					} else {
						byte[] _filename = filename;
						if (!this.fEncoding_is_utf8) {
							f = Util.byte2str(_filename, this.fEncoding);
							_filename = Util.str2byte(f, UTF8);
						}
						find = Util.glob(pattern, _filename);
					}

					if (find) {
						if (f == null) {
							f = Util.byte2str(filename, this.fEncoding);
						}
						String l = null;
						if (longname == null) {
							// TODO: we need to generate long name from attrs
							// for the sftp protocol 4(and later).
							l = attrs.toString() + " " + f;
						} else {
							l = Util.byte2str(longname, this.fEncoding);
						}

						cancel = selector.select(new LsEntry(f, l, attrs));
					}

					count--;
				}
			}
			this._sendCLOSE(handle, header);

			/*
			 * if(v.size()==1 && pattern_has_wildcard){
			 * LsEntry le=(LsEntry)v.elementAt(0);
			 * if(le.getAttrs().isDir()){
			 * String f=le.getFilename();
			 * if(isPattern(f)){
			 * f=Util.quote(f);
			 * }
			 * if(!dir.endsWith("/")){
			 * dir+="/";
			 * }
			 * v=null;
			 * return ls(dir+f);
			 * }
			 * }
			 */

		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public String readlink(String path) throws SftpException {
		try {
			if (this.server_version < 3) {
				throw new SftpException(SSH_FX_OP_UNSUPPORTED,
						"The remote sshd is too old to support symlink operation.");
			}

			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			path = this.isUnique(path);

			this.sendREADLINK(Util.str2byte(path, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			if (type == SSH_FXP_NAME) {
				final int count = this.buf.getInt(); // count
				byte[] filename = null;
				for (int i = 0; i < count; i++) {
					filename = this.buf.getString();
					if (this.server_version <= 3) {
						final byte[] longname = this.buf.getString();
					}
					SftpATTRS.getATTR(this.buf);
				}
				return Util.byte2str(filename, this.fEncoding);
			}

			final int i = this.buf.getInt();
			this.throwStatusError(this.buf, i);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		return null;
	}

	public void symlink(String oldpath, String newpath) throws SftpException {
		if (this.server_version < 3) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED,
					"The remote sshd is too old to support symlink operation.");
		}

		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			String _oldpath = this.remoteAbsolutePath(oldpath);
			newpath = this.remoteAbsolutePath(newpath);

			_oldpath = this.isUnique(_oldpath);
			if (oldpath.charAt(0) != '/') { // relative path
				final String cwd = this.getCwd();
				oldpath = _oldpath.substring(cwd.length() + (cwd.endsWith("/") ? 0 : 1));
			} else {
				oldpath = _oldpath;
			}

			if (this.isPattern(newpath)) {
				throw new SftpException(SSH_FX_FAILURE, newpath);
			}
			newpath = Util.unquote(newpath);

			this.sendSYMLINK(Util.str2byte(oldpath, this.fEncoding),
					Util.str2byte(newpath, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}

			final int i = this.buf.getInt();
			if (i == SSH_FX_OK) {
				return;
			}
			this.throwStatusError(this.buf, i);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void hardlink(String oldpath, String newpath) throws SftpException {
		if (!this.extension_hardlink) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED,
					"hardlink@openssh.com is not supported");
		}

		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			String _oldpath = this.remoteAbsolutePath(oldpath);
			newpath = this.remoteAbsolutePath(newpath);

			_oldpath = this.isUnique(_oldpath);
			if (oldpath.charAt(0) != '/') { // relative path
				final String cwd = this.getCwd();
				oldpath = _oldpath.substring(cwd.length() + (cwd.endsWith("/") ? 0 : 1));
			} else {
				oldpath = _oldpath;
			}

			if (this.isPattern(newpath)) {
				throw new SftpException(SSH_FX_FAILURE, newpath);
			}
			newpath = Util.unquote(newpath);

			this.sendHARDLINK(Util.str2byte(oldpath, this.fEncoding),
					Util.str2byte(newpath, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}

			final int i = this.buf.getInt();
			if (i == SSH_FX_OK) {
				return;
			}
			this.throwStatusError(this.buf, i);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void rename(String oldpath, String newpath) throws SftpException {
		if (this.server_version < 2) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED,
					"The remote sshd is too old to support rename operation.");
		}

		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			oldpath = this.remoteAbsolutePath(oldpath);
			newpath = this.remoteAbsolutePath(newpath);

			oldpath = this.isUnique(oldpath);

			final Vector v = this.glob_remote(newpath);
			final int vsize = v.size();
			if (vsize >= 2) {
				throw new SftpException(SSH_FX_FAILURE, v.toString());
			}
			if (vsize == 1) {
				newpath = (String) (v.elementAt(0));
			} else { // vsize==0
				if (this.isPattern(newpath)) {
					throw new SftpException(SSH_FX_FAILURE, newpath);
				}
				newpath = Util.unquote(newpath);
			}

			this.sendRENAME(Util.str2byte(oldpath, this.fEncoding),
					Util.str2byte(newpath, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}

			final int i = this.buf.getInt();
			if (i == SSH_FX_OK) {
				return;
			}
			this.throwStatusError(this.buf, i);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void rm(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();

			Header header = new Header();

			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));
				this.sendREMOVE(Util.str2byte(path, this.fEncoding));

				header = this.header(this.buf, header);
				final int length = header.length;
				final int type = header.type;

				this.fill(this.buf, length);

				if (type != SSH_FXP_STATUS) {
					throw new SftpException(SSH_FX_FAILURE, "");
				}
				final int i = this.buf.getInt();
				if (i != SSH_FX_OK) {
					this.throwStatusError(this.buf, i);
				}
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private boolean isRemoteDir(final String path) {
		try {
			this.sendSTAT(Util.str2byte(path, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_ATTRS) {
				return false;
			}
			final SftpATTRS attr = SftpATTRS.getATTR(this.buf);
			return attr.isDir();
		} catch (final Exception e) {}
		return false;
	}

	public void chgrp(final int gid, String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();
			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));

				final SftpATTRS attr = this._stat(path);

				attr.setFLAGS(0);
				attr.setUIDGID(attr.uid, gid);
				this._setStat(path, attr);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void chown(final int uid, String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();
			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));

				final SftpATTRS attr = this._stat(path);

				attr.setFLAGS(0);
				attr.setUIDGID(uid, attr.gid);
				this._setStat(path, attr);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void chmod(final int permissions, String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();
			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));

				final SftpATTRS attr = this._stat(path);

				attr.setFLAGS(0);
				attr.setPERMISSIONS(permissions);
				this._setStat(path, attr);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void setMtime(String path, final int mtime) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();
			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));

				final SftpATTRS attr = this._stat(path);

				attr.setFLAGS(0);
				attr.setACMODTIME(attr.getATime(), mtime);
				this._setStat(path, attr);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void rmdir(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();

			Header header = new Header();

			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));
				this.sendRMDIR(Util.str2byte(path, this.fEncoding));

				header = this.header(this.buf, header);
				final int length = header.length;
				final int type = header.type;

				this.fill(this.buf, length);

				if (type != SSH_FXP_STATUS) {
					throw new SftpException(SSH_FX_FAILURE, "");
				}

				final int i = this.buf.getInt();
				if (i != SSH_FX_OK) {
					this.throwStatusError(this.buf, i);
				}
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public void mkdir(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			this.sendMKDIR(Util.str2byte(path, this.fEncoding), null);

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}

			final int i = this.buf.getInt();
			if (i == SSH_FX_OK) {
				return;
			}
			this.throwStatusError(this.buf, i);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public SftpATTRS stat(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);
			path = this.isUnique(path);

			return this._stat(path);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		// return null;
	}

	private SftpATTRS _stat(final byte[] path) throws SftpException {
		try {

			this.sendSTAT(path);

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_ATTRS) {
				if (type == SSH_FXP_STATUS) {
					final int i = this.buf.getInt();
					this.throwStatusError(this.buf, i);
				}
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			final SftpATTRS attr = SftpATTRS.getATTR(this.buf);
			return attr;
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		// return null;
	}

	private SftpATTRS _stat(final String path) throws SftpException {
		return this._stat(Util.str2byte(path, this.fEncoding));
	}

	public SftpStatVFS statVFS(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);
			path = this.isUnique(path);

			return this._statVFS(path);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		// return null;
	}

	private SftpStatVFS _statVFS(final byte[] path) throws SftpException {
		if (!this.extension_statvfs) {
			throw new SftpException(SSH_FX_OP_UNSUPPORTED,
					"statvfs@openssh.com is not supported");
		}

		try {

			this.sendSTATVFS(path);

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != (SSH_FXP_EXTENDED_REPLY & 0xff)) {
				if (type == SSH_FXP_STATUS) {
					final int i = this.buf.getInt();
					this.throwStatusError(this.buf, i);
				}
				throw new SftpException(SSH_FX_FAILURE, "");
			} else {
				final SftpStatVFS stat = SftpStatVFS.getStatVFS(this.buf);
				return stat;
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		// return null;
	}

	private SftpStatVFS _statVFS(final String path) throws SftpException {
		return this._statVFS(Util.str2byte(path, this.fEncoding));
	}

	public SftpATTRS lstat(String path) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);
			path = this.isUnique(path);

			return this._lstat(path);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private SftpATTRS _lstat(final String path) throws SftpException {
		try {
			this.sendLSTAT(Util.str2byte(path, this.fEncoding));

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_ATTRS) {
				if (type == SSH_FXP_STATUS) {
					final int i = this.buf.getInt();
					this.throwStatusError(this.buf, i);
				}
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			final SftpATTRS attr = SftpATTRS.getATTR(this.buf);
			return attr;
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private byte[] _realpath(final String path) throws SftpException, IOException, Exception {
		this.sendREALPATH(Util.str2byte(path, this.fEncoding));

		Header header = new Header();
		header = this.header(this.buf, header);
		final int length = header.length;
		final int type = header.type;

		this.fill(this.buf, length);

		if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME) {
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		int i;
		if (type == SSH_FXP_STATUS) {
			i = this.buf.getInt();
			this.throwStatusError(this.buf, i);
		}
		i = this.buf.getInt(); // count

		byte[] str = null;
		while (i-- > 0) {
			str = this.buf.getString(); // absolute path;
			if (this.server_version <= 3) {
				final byte[] lname = this.buf.getString(); // long filename
			}
			final SftpATTRS attr = SftpATTRS.getATTR(this.buf); // dummy attribute
		}
		return str;
	}

	public void setStat(String path, final SftpATTRS attr) throws SftpException {
		try {
			((MyPipedInputStream) this.io_in).updateReadSide();

			path = this.remoteAbsolutePath(path);

			final Vector v = this.glob_remote(path);
			final int vsize = v.size();
			for (int j = 0; j < vsize; j++) {
				path = (String) (v.elementAt(j));
				this._setStat(path, attr);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	private void _setStat(final String path, final SftpATTRS attr) throws SftpException {
		try {
			this.sendSETSTAT(Util.str2byte(path, this.fEncoding), attr);

			Header header = new Header();
			header = this.header(this.buf, header);
			final int length = header.length;
			final int type = header.type;

			this.fill(this.buf, length);

			if (type != SSH_FXP_STATUS) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			final int i = this.buf.getInt();
			if (i != SSH_FX_OK) {
				this.throwStatusError(this.buf, i);
			}
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public String pwd() throws SftpException {
		return this.getCwd();
	}

	public String lpwd() {
		return this.lcwd;
	}

	public String version() {
		return this.version;
	}

	public String getHome() throws SftpException {
		if (this.home == null) {
			try {
				((MyPipedInputStream) this.io_in).updateReadSide();

				final byte[] _home = this._realpath("");
				this.home = Util.byte2str(_home, this.fEncoding);
			} catch (final Exception e) {
				if (e instanceof SftpException) {
					throw (SftpException) e;
				}
				if (e instanceof Throwable) {
					throw new SftpException(SSH_FX_FAILURE, "", e);
				}
				throw new SftpException(SSH_FX_FAILURE, "");
			}
		}
		return this.home;
	}

	private String getCwd() throws SftpException {
		if (this.cwd == null) {
			this.cwd = this.getHome();
		}
		return this.cwd;
	}

	private void setCwd(final String cwd) {
		this.cwd = cwd;
	}

	private void read(final byte[] buf, int s, int l) throws IOException, SftpException {
		int i = 0;
		while (l > 0) {
			i = this.io_in.read(buf, s, l);
			if (i <= 0) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			s += i;
			l -= i;
		}
	}

	private boolean checkStatus(final int[] ackid, Header header) throws IOException, SftpException {
		header = this.header(this.buf, header);
		final int length = header.length;
		final int type = header.type;
		if (ackid != null) {
			ackid[0] = header.rid;
		}

		this.fill(this.buf, length);

		if (type != SSH_FXP_STATUS) {
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		final int i = this.buf.getInt();
		if (i != SSH_FX_OK) {
			this.throwStatusError(this.buf, i);
		}
		return true;
	}

	private boolean _sendCLOSE(final byte[] handle, final Header header) throws Exception {
		this.sendCLOSE(handle);
		return this.checkStatus(null, header);
	}

	private void sendINIT() throws Exception {
		this.packet.reset();
		this.putHEAD(SSH_FXP_INIT, 5);
		this.buf.putInt(3); // version 3
		this.getSession().write(this.packet, this, 5 + 4);
	}

	private void sendREALPATH(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_REALPATH, path);
	}

	private void sendSTAT(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_STAT, path);
	}

	private void sendSTATVFS(final byte[] path) throws Exception {
		this.sendPacketPath((byte) 0, path, "statvfs@openssh.com");
	}

	/*
	 * private void sendFSTATVFS(byte[] handle) throws Exception{
	 * sendPacketPath((byte)0, handle, "fstatvfs@openssh.com");
	 * }
	 */
	private void sendLSTAT(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_LSTAT, path);
	}

	private void sendFSTAT(final byte[] handle) throws Exception {
		this.sendPacketPath(SSH_FXP_FSTAT, handle);
	}

	private void sendSETSTAT(final byte[] path, final SftpATTRS attr) throws Exception {
		this.packet.reset();
		this.putHEAD(SSH_FXP_SETSTAT, 9 + path.length + attr.length());
		this.buf.putInt(this.seq++);
		this.buf.putString(path); // path
		attr.dump(this.buf);
		this.getSession().write(this.packet, this, 9 + path.length + attr.length() + 4);
	}

	private void sendREMOVE(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_REMOVE, path);
	}

	private void sendMKDIR(final byte[] path, final SftpATTRS attr) throws Exception {
		this.packet.reset();
		this.putHEAD(SSH_FXP_MKDIR, 9 + path.length + (attr != null ? attr.length() : 4));
		this.buf.putInt(this.seq++);
		this.buf.putString(path); // path
		if (attr != null) {
			attr.dump(this.buf);
		} else {
			this.buf.putInt(0);
		}
		this.getSession().write(this.packet, this, 9 + path.length + (attr != null ? attr.length() : 4) + 4);
	}

	private void sendRMDIR(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_RMDIR, path);
	}

	private void sendSYMLINK(final byte[] p1, final byte[] p2) throws Exception {
		this.sendPacketPath(SSH_FXP_SYMLINK, p1, p2);
	}

	private void sendHARDLINK(final byte[] p1, final byte[] p2) throws Exception {
		this.sendPacketPath((byte) 0, p1, p2, "hardlink@openssh.com");
	}

	private void sendREADLINK(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_READLINK, path);
	}

	private void sendOPENDIR(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_OPENDIR, path);
	}

	private void sendREADDIR(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_READDIR, path);
	}

	private void sendRENAME(final byte[] p1, final byte[] p2) throws Exception {
		this.sendPacketPath(SSH_FXP_RENAME, p1, p2,
				this.extension_posix_rename ? "posix-rename@openssh.com" : null);
	}

	private void sendCLOSE(final byte[] path) throws Exception {
		this.sendPacketPath(SSH_FXP_CLOSE, path);
	}

	private void sendOPENR(final byte[] path) throws Exception {
		this.sendOPEN(path, SSH_FXF_READ);
	}

	private void sendOPENW(final byte[] path) throws Exception {
		this.sendOPEN(path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC);
	}

	private void sendOPENA(final byte[] path) throws Exception {
		this.sendOPEN(path, SSH_FXF_WRITE | /* SSH_FXF_APPEND| */SSH_FXF_CREAT);
	}

	private void sendOPEN(final byte[] path, final int mode) throws Exception {
		this.packet.reset();
		this.putHEAD(SSH_FXP_OPEN, 17 + path.length);
		this.buf.putInt(this.seq++);
		this.buf.putString(path);
		this.buf.putInt(mode);
		this.buf.putInt(0); // attrs
		this.getSession().write(this.packet, this, 17 + path.length + 4);
	}

	private void sendPacketPath(final byte fxp, final byte[] path) throws Exception {
		this.sendPacketPath(fxp, path, (String) null);
	}

	private void sendPacketPath(final byte fxp, final byte[] path, final String extension) throws Exception {
		this.packet.reset();
		int len = 9 + path.length;
		if (extension == null) {
			this.putHEAD(fxp, len);
			this.buf.putInt(this.seq++);
		} else {
			len += (4 + extension.length());
			this.putHEAD(SSH_FXP_EXTENDED, len);
			this.buf.putInt(this.seq++);
			this.buf.putString(Util.str2byte(extension));
		}
		this.buf.putString(path); // path
		this.getSession().write(this.packet, this, len + 4);
	}

	private void sendPacketPath(final byte fxp, final byte[] p1, final byte[] p2) throws Exception {
		this.sendPacketPath(fxp, p1, p2, null);
	}

	private void sendPacketPath(final byte fxp, final byte[] p1, final byte[] p2, final String extension) throws Exception {
		this.packet.reset();
		int len = 13 + p1.length + p2.length;
		if (extension == null) {
			this.putHEAD(fxp, len);
			this.buf.putInt(this.seq++);
		} else {
			len += (4 + extension.length());
			this.putHEAD(SSH_FXP_EXTENDED, len);
			this.buf.putInt(this.seq++);
			this.buf.putString(Util.str2byte(extension));
		}
		this.buf.putString(p1);
		this.buf.putString(p2);
		this.getSession().write(this.packet, this, len + 4);
	}

	private int sendWRITE(final byte[] handle, final long offset,
			final byte[] data, final int start, final int length) throws Exception {
		int _length = length;
		this.opacket.reset();
		if (this.obuf.buffer.length < this.obuf.index + 13 + 21 + handle.length + length + Session.buffer_margin) {
			_length = this.obuf.buffer.length - (this.obuf.index + 13 + 21 + handle.length + Session.buffer_margin);
			// System.err.println("_length="+_length+" length="+length);
		}

		this.putHEAD(this.obuf, SSH_FXP_WRITE, 21 + handle.length + _length); // 14
		this.obuf.putInt(this.seq++); // 4
		this.obuf.putString(handle); // 4+handle.length
		this.obuf.putLong(offset); // 8
		if (this.obuf.buffer != data) {
			this.obuf.putString(data, start, _length); // 4+_length
		} else {
			this.obuf.putInt(_length);
			this.obuf.skip(_length);
		}
		this.getSession().write(this.opacket, this, 21 + handle.length + _length + 4);
		return _length;
	}

	private void sendREAD(final byte[] handle, final long offset, final int length) throws Exception {
		this.sendREAD(handle, offset, length, null);
	}

	private void sendREAD(final byte[] handle, final long offset, final int length,
			final RequestQueue rrq) throws Exception {
		this.packet.reset();
		this.putHEAD(SSH_FXP_READ, 21 + handle.length);
		this.buf.putInt(this.seq++);
		this.buf.putString(handle);
		this.buf.putLong(offset);
		this.buf.putInt(length);
		this.getSession().write(this.packet, this, 21 + handle.length + 4);
		if (rrq != null) {
			rrq.add(this.seq - 1, offset, length);
		}
	}

	private void putHEAD(final Buffer buf, final byte type, final int length) throws Exception {
		buf.putByte((byte) Session.SSH_MSG_CHANNEL_DATA);
		buf.putInt(this.recipient);
		buf.putInt(length + 4);
		buf.putInt(length);
		buf.putByte(type);
	}

	private void putHEAD(final byte type, final int length) throws Exception {
		this.putHEAD(this.buf, type, length);
	}

	private Vector glob_remote(final String _path) throws Exception {
		final Vector v = new Vector();
		int i = 0;

		final int foo = _path.lastIndexOf('/');
		if (foo < 0) { // it is not absolute path.
			v.addElement(Util.unquote(_path));
			return v;
		}

		String dir = _path.substring(0, ((foo == 0) ? 1 : foo));
		final String _pattern = _path.substring(foo + 1);

		dir = Util.unquote(dir);

		byte[] pattern = null;
		final byte[][] _pattern_utf8 = new byte[1][];
		final boolean pattern_has_wildcard = this.isPattern(_pattern, _pattern_utf8);

		if (!pattern_has_wildcard) {
			if (!dir.equals("/")) {
				dir += "/";
			}
			v.addElement(dir + Util.unquote(_pattern));
			return v;
		}

		pattern = _pattern_utf8[0];

		this.sendOPENDIR(Util.str2byte(dir, this.fEncoding));

		Header header = new Header();
		header = this.header(this.buf, header);
		int length = header.length;
		int type = header.type;

		this.fill(this.buf, length);

		if (type != SSH_FXP_STATUS && type != SSH_FXP_HANDLE) {
			throw new SftpException(SSH_FX_FAILURE, "");
		}
		if (type == SSH_FXP_STATUS) {
			i = this.buf.getInt();
			this.throwStatusError(this.buf, i);
		}

		final byte[] handle = this.buf.getString(); // filename
		String pdir = null; // parent directory

		while (true) {
			this.sendREADDIR(handle);
			header = this.header(this.buf, header);
			length = header.length;
			type = header.type;

			if (type != SSH_FXP_STATUS && type != SSH_FXP_NAME) {
				throw new SftpException(SSH_FX_FAILURE, "");
			}
			if (type == SSH_FXP_STATUS) {
				this.fill(this.buf, length);
				break;
			}

			this.buf.rewind();
			this.fill(this.buf.buffer, 0, 4);
			length -= 4;
			int count = this.buf.getInt();

			byte[] str;
			final int flags;

			this.buf.reset();
			while (count > 0) {
				if (length > 0) {
					this.buf.shift();
					final int j = (this.buf.buffer.length > (this.buf.index + length)) ? length : (this.buf.buffer.length - this.buf.index);
					i = this.io_in.read(this.buf.buffer, this.buf.index, j);
					if (i <= 0) {
						break;
					}
					this.buf.index += i;
					length -= i;
				}

				final byte[] filename = this.buf.getString();
				// System.err.println("filename: "+new String(filename));
				if (this.server_version <= 3) {
					str = this.buf.getString(); // longname
				}
				final SftpATTRS attrs = SftpATTRS.getATTR(this.buf);

				byte[] _filename = filename;
				String f = null;
				boolean found = false;

				if (!this.fEncoding_is_utf8) {
					f = Util.byte2str(filename, this.fEncoding);
					_filename = Util.str2byte(f, UTF8);
				}
				found = Util.glob(pattern, _filename);

				if (found) {
					if (f == null) {
						f = Util.byte2str(filename, this.fEncoding);
					}
					if (pdir == null) {
						pdir = dir;
						if (!pdir.endsWith("/")) {
							pdir += "/";
						}
					}
					v.addElement(pdir + f);
				}
				count--;
			}
		}
		if (this._sendCLOSE(handle, header)) {
			return v;
		}
		return null;
	}

	private boolean isPattern(final byte[] path) {
		final int length = path.length;
		int i = 0;
		while (i < length) {
			if (path[i] == '*' || path[i] == '?') {
				return true;
			}
			if (path[i] == '\\' && (i + 1) < length) {
				i++;
			}
			i++;
		}
		return false;
	}

	private Vector glob_local(final String _path) throws Exception {
		// System.err.println("glob_local: "+_path);
		final Vector v = new Vector();
		final byte[] path = Util.str2byte(_path, UTF8);
		int i = path.length - 1;
		while (i >= 0) {
			if (path[i] != '*' && path[i] != '?') {
				i--;
				continue;
			}
			if (!fs_is_bs &&
					i > 0 && path[i - 1] == '\\') {
				i--;
				if (i > 0 && path[i - 1] == '\\') {
					i--;
					i--;
					continue;
				}
			}
			break;
		}

		if (i < 0) {
			v.addElement(fs_is_bs ? _path : Util.unquote(_path));
			return v;
		}

		while (i >= 0) {
			if (path[i] == file_separatorc ||
					(fs_is_bs && path[i] == '/')) { // On Windows, '/' is also the separator.
				break;
			}
			i--;
		}

		if (i < 0) {
			v.addElement(fs_is_bs ? _path : Util.unquote(_path));
			return v;
		}

		byte[] dir;
		if (i == 0) {
			dir = new byte[] { (byte) file_separatorc };
		} else {
			dir = new byte[i];
			System.arraycopy(path, 0, dir, 0, i);
		}

		final byte[] pattern = new byte[path.length - i - 1];
		System.arraycopy(path, i + 1, pattern, 0, pattern.length);

		// System.err.println("dir: "+new String(dir)+" pattern: "+new String(pattern));
		try {
			final String[] children = (new File(Util.byte2str(dir, UTF8))).list();
			final String pdir = Util.byte2str(dir) + file_separator;
			for (int j = 0; j < children.length; j++) {
				// System.err.println("children: "+children[j]);
				if (Util.glob(pattern, Util.str2byte(children[j], UTF8))) {
					v.addElement(pdir + children[j]);
				}
			}
		} catch (final Exception e) {}
		return v;
	}

	private void throwStatusError(final Buffer buf, final int i) throws SftpException {
		if (this.server_version >= 3 && // WindRiver's sftp will send invalid
				buf.getLength() >= 4) { // SSH_FXP_STATUS packet.
			final byte[] str = buf.getString();
			// byte[] tag=buf.getString();
			throw new SftpException(i, Util.byte2str(str, UTF8));
		} else {
			throw new SftpException(i, "Failure");
		}
	}

	private static boolean isLocalAbsolutePath(final String path) {
		return (new File(path)).isAbsolute();
	}

	@Override
	public void disconnect() {
		super.disconnect();
	}

	private boolean isPattern(final String path, final byte[][] utf8) {
		final byte[] _path = Util.str2byte(path, UTF8);
		if (utf8 != null) {
			utf8[0] = _path;
		}
		return this.isPattern(_path);
	}

	private boolean isPattern(final String path) {
		return this.isPattern(path, null);
	}

	private void fill(final Buffer buf, final int len) throws IOException {
		buf.reset();
		this.fill(buf.buffer, 0, len);
		buf.skip(len);
	}

	private int fill(final byte[] buf, int s, int len) throws IOException {
		int i = 0;
		final int foo = s;
		while (len > 0) {
			i = this.io_in.read(buf, s, len);
			if (i <= 0) {
				throw new IOException("inputstream is closed");
				// return (s-foo)==0 ? i : s-foo;
			}
			s += i;
			len -= i;
		}
		return s - foo;
	}

	private void skip(long foo) throws IOException {
		while (foo > 0) {
			final long bar = this.io_in.skip(foo);
			if (bar <= 0) {
				break;
			}
			foo -= bar;
		}
	}

	class Header {

		int length;
		int type;
		int rid;
	}

	private Header header(final Buffer buf, final Header header) throws IOException {
		buf.rewind();
		final int i = this.fill(buf.buffer, 0, 9);
		header.length = buf.getInt() - 5;
		header.type = buf.getByte() & 0xff;
		header.rid = buf.getInt();
		return header;
	}

	private String remoteAbsolutePath(final String path) throws SftpException {
		if (path.charAt(0) == '/') {
			return path;
		}
		final String cwd = this.getCwd();
		// if(cwd.equals(getHome())) return path;
		if (cwd.endsWith("/")) {
			return cwd + path;
		}
		return cwd + "/" + path;
	}

	private String localAbsolutePath(final String path) {
		if (isLocalAbsolutePath(path)) {
			return path;
		}
		if (this.lcwd.endsWith(file_separator)) {
			return this.lcwd + path;
		}
		return this.lcwd + file_separator + path;
	}

	/**
	 * This method will check if the given string can be expanded to the
	 * unique string. If it can be expanded to mutiple files, SftpException
	 * will be thrown.
	 * 
	 * @return the returned string is unquoted.
	 */
	private String isUnique(final String path) throws SftpException, Exception {
		final Vector v = this.glob_remote(path);
		if (v.size() != 1) {
			throw new SftpException(SSH_FX_FAILURE, path + " is not unique: " + v.toString());
		}
		return (String) (v.elementAt(0));
	}

	public int getServerVersion() throws SftpException {
		if (!this.isConnected()) {
			throw new SftpException(SSH_FX_FAILURE, "The channel is not connected.");
		}
		return this.server_version;
	}

	public void setFilenameEncoding(String encoding) throws SftpException {
		final int sversion = this.getServerVersion();
		if (3 <= sversion && sversion <= 5 &&
				!encoding.equals(UTF8)) {
			throw new SftpException(SSH_FX_FAILURE,
					"The encoding can not be changed for this sftp server.");
		}
		if (encoding.equals(UTF8)) {
			encoding = UTF8;
		}
		this.fEncoding = encoding;
		this.fEncoding_is_utf8 = this.fEncoding.equals(UTF8);
	}

	public String getExtension(final String key) {
		if (this.extensions == null) {
			return null;
		}
		return (String) this.extensions.get(key);
	}

	public String realpath(final String path) throws SftpException {
		try {
			final byte[] _path = this._realpath(this.remoteAbsolutePath(path));
			return Util.byte2str(_path, this.fEncoding);
		} catch (final Exception e) {
			if (e instanceof SftpException) {
				throw (SftpException) e;
			}
			if (e instanceof Throwable) {
				throw new SftpException(SSH_FX_FAILURE, "", e);
			}
			throw new SftpException(SSH_FX_FAILURE, "");
		}
	}

	public class LsEntry implements Comparable {

		private String filename;
		private String longname;
		private SftpATTRS attrs;

		LsEntry(final String filename, final String longname, final SftpATTRS attrs) {
			this.setFilename(filename);
			this.setLongname(longname);
			this.setAttrs(attrs);
		}

		public String getFilename() {
			return this.filename;
		};

		void setFilename(final String filename) {
			this.filename = filename;
		};

		public String getLongname() {
			return this.longname;
		};

		void setLongname(final String longname) {
			this.longname = longname;
		};

		public SftpATTRS getAttrs() {
			return this.attrs;
		};

		void setAttrs(final SftpATTRS attrs) {
			this.attrs = attrs;
		};

		@Override
		public String toString() {
			return this.longname;
		}

		@Override
		public int compareTo(final Object o) throws ClassCastException {
			if (o instanceof LsEntry) {
				return this.filename.compareTo(((LsEntry) o).getFilename());
			}
			throw new ClassCastException("a decendent of LsEntry must be given.");
		}
	}

	/**
	 * This interface will be passed as an argument for <code>ls</code> method.
	 *
	 * @see ChannelSftp.LsEntry
	 * @see #ls(String, ChannelSftp.LsEntrySelector)
	 * @since 0.1.47
	 */
	public interface LsEntrySelector {

		public final int CONTINUE = 0;
		public final int BREAK = 1;

		/**
		 * <p> The <code>select</code> method will be invoked in <code>ls</code>
		 * method for each file entry. If this method returns BREAK,
		 * <code>ls</code> will be canceled.
		 * 
		 * @param entry one of entry from ls
		 * @return if BREAK is returned, the 'ls' operation will be canceled.
		 */
		public int select(LsEntry entry);
	}
}
