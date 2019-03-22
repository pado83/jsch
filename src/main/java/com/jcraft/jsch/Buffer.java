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

public class Buffer {

	final byte[] tmp = new byte[4];
	byte[] buffer;
	int index;
	int s;

	public Buffer(final int size) {
		this.buffer = new byte[size];
		this.index = 0;
		this.s = 0;
	}

	public Buffer(final byte[] buffer) {
		this.buffer = buffer;
		this.index = 0;
		this.s = 0;
	}

	public Buffer() {
		this(1024 * 10 * 2);
	}

	public void putByte(final byte foo) {
		this.buffer[this.index++] = foo;
	}

	public void putByte(final byte[] foo) {
		this.putByte(foo, 0, foo.length);
	}

	public void putByte(final byte[] foo, final int begin, final int length) {
		System.arraycopy(foo, begin, this.buffer, this.index, length);
		this.index += length;
	}

	public void putString(final byte[] foo) {
		this.putString(foo, 0, foo.length);
	}

	public void putString(final byte[] foo, final int begin, final int length) {
		this.putInt(length);
		this.putByte(foo, begin, length);
	}

	public void putInt(final int val) {
		this.tmp[0] = (byte) (val >>> 24);
		this.tmp[1] = (byte) (val >>> 16);
		this.tmp[2] = (byte) (val >>> 8);
		this.tmp[3] = (byte) (val);
		System.arraycopy(this.tmp, 0, this.buffer, this.index, 4);
		this.index += 4;
	}

	public void putLong(final long val) {
		this.tmp[0] = (byte) (val >>> 56);
		this.tmp[1] = (byte) (val >>> 48);
		this.tmp[2] = (byte) (val >>> 40);
		this.tmp[3] = (byte) (val >>> 32);
		System.arraycopy(this.tmp, 0, this.buffer, this.index, 4);
		this.tmp[0] = (byte) (val >>> 24);
		this.tmp[1] = (byte) (val >>> 16);
		this.tmp[2] = (byte) (val >>> 8);
		this.tmp[3] = (byte) (val);
		System.arraycopy(this.tmp, 0, this.buffer, this.index + 4, 4);
		this.index += 8;
	}

	void skip(final int n) {
		this.index += n;
	}

	void putPad(int n) {
		while (n > 0) {
			this.buffer[this.index++] = (byte) 0;
			n--;
		}
	}

	public void putMPInt(final byte[] foo) {
		int i = foo.length;
		if ((foo[0] & 0x80) != 0) {
			i++;
			this.putInt(i);
			this.putByte((byte) 0);
		} else {
			this.putInt(i);
		}
		this.putByte(foo);
	}

	public int getLength() {
		return this.index - this.s;
	}

	public int getOffSet() {
		return this.s;
	}

	public void setOffSet(final int s) {
		this.s = s;
	}

	public long getLong() {
		long foo = this.getInt() & 0xffffffffL;
		foo = ((foo << 32)) | (this.getInt() & 0xffffffffL);
		return foo;
	}

	public int getInt() {
		int foo = this.getShort();
		foo = ((foo << 16) & 0xffff0000) | (this.getShort() & 0xffff);
		return foo;
	}

	public long getUInt() {
		long foo = 0L;
		long bar = 0L;
		foo = this.getByte();
		foo = ((foo << 8) & 0xff00) | (this.getByte() & 0xff);
		bar = this.getByte();
		bar = ((bar << 8) & 0xff00) | (this.getByte() & 0xff);
		foo = ((foo << 16) & 0xffff0000) | (bar & 0xffff);
		return foo;
	}

	int getShort() {
		int foo = this.getByte();
		foo = ((foo << 8) & 0xff00) | (this.getByte() & 0xff);
		return foo;
	}

	public int getByte() {
		return (this.buffer[this.s++] & 0xff);
	}

	public void getByte(final byte[] foo) {
		this.getByte(foo, 0, foo.length);
	}

	void getByte(final byte[] foo, final int start, final int len) {
		System.arraycopy(this.buffer, this.s, foo, start, len);
		this.s += len;
	}

	public int getByte(final int len) {
		final int foo = this.s;
		this.s += len;
		return foo;
	}

	public byte[] getMPInt() {
		int i = this.getInt(); // uint32
		if (i < 0 || // bigger than 0x7fffffff
				i > 8 * 1024) {
			// TODO: an exception should be thrown.
			i = 8 * 1024; // the session will be broken, but working around OOME.
		}
		final byte[] foo = new byte[i];
		this.getByte(foo, 0, i);
		return foo;
	}

	public byte[] getMPIntBits() {
		final int bits = this.getInt();
		final int bytes = (bits + 7) / 8;
		byte[] foo = new byte[bytes];
		this.getByte(foo, 0, bytes);
		if ((foo[0] & 0x80) != 0) {
			final byte[] bar = new byte[foo.length + 1];
			bar[0] = 0; // ??
			System.arraycopy(foo, 0, bar, 1, foo.length);
			foo = bar;
		}
		return foo;
	}

	public byte[] getString() {
		int i = this.getInt(); // uint32
		if (i < 0 || // bigger than 0x7fffffff
				i > 256 * 1024) {
			// TODO: an exception should be thrown.
			i = 256 * 1024; // the session will be broken, but working around OOME.
		}
		final byte[] foo = new byte[i];
		this.getByte(foo, 0, i);
		return foo;
	}

	byte[] getString(final int[] start, final int[] len) {
		final int i = this.getInt();
		start[0] = this.getByte(i);
		len[0] = i;
		return this.buffer;
	}

	public void reset() {
		this.index = 0;
		this.s = 0;
	}

	public void shift() {
		if (this.s == 0) {
			return;
		}
		System.arraycopy(this.buffer, this.s, this.buffer, 0, this.index - this.s);
		this.index = this.index - this.s;
		this.s = 0;
	}

	void rewind() {
		this.s = 0;
	}

	byte getCommand() {
		return this.buffer[5];
	}

	void checkFreeSize(final int n) {
		final int size = this.index + n + Session.buffer_margin;
		if (this.buffer.length < size) {
			int i = this.buffer.length * 2;
			if (i < size) {
				i = size;
			}
			final byte[] tmp = new byte[i];
			System.arraycopy(this.buffer, 0, tmp, 0, this.index);
			this.buffer = tmp;
		}
	}

	byte[][] getBytes(final int n, final String msg) throws JSchException {
		final byte[][] tmp = new byte[n][];
		for (int i = 0; i < n; i++) {
			final int j = this.getInt();
			if (this.getLength() < j) {
				throw new JSchException(msg);
			}
			tmp[i] = new byte[j];
			this.getByte(tmp[i]);
		}
		return tmp;
	}

	/*
	 * static Buffer fromBytes(byte[]... args){
	 * int length = args.length*4;
	 * for(int i = 0; i < args.length; i++){
	 * length += args[i].length;
	 * }
	 * Buffer buf = new Buffer(length);
	 * for(int i = 0; i < args.length; i++){
	 * buf.putString(args[i]);
	 * }
	 * return buf;
	 * }
	 */

	static Buffer fromBytes(final byte[][] args) {
		int length = args.length * 4;
		for (int i = 0; i < args.length; i++) {
			length += args[i].length;
		}
		final Buffer buf = new Buffer(length);
		for (int i = 0; i < args.length; i++) {
			buf.putString(args[i]);
		}
		return buf;
	}

	/*
	 * static String[] chars={
	 * "0","1","2","3","4","5","6","7","8","9", "a","b","c","d","e","f"
	 * };
	 * static void dump_buffer(){
	 * int foo;
	 * for(int i=0; i<tmp_buffer_index; i++){
	 * foo=tmp_buffer[i]&0xff;
	 * System.err.print(chars[(foo>>>4)&0xf]);
	 * System.err.print(chars[foo&0xf]);
	 * if(i%16==15){
	 * System.err.println("");
	 * continue;
	 * }
	 * if(i>0 && i%2==1){
	 * System.err.print(" ");
	 * }
	 * }
	 * System.err.println("");
	 * }
	 * static void dump(byte[] b){
	 * dump(b, 0, b.length);
	 * }
	 * static void dump(byte[] b, int s, int l){
	 * for(int i=s; i<s+l; i++){
	 * System.err.print(Integer.toHexString(b[i]&0xff)+":");
	 * }
	 * System.err.println("");
	 * }
	 */

}
