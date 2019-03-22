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

public class Packet {

	private static Random random = null;

	static void setRandom(final Random foo) {
		random = foo;
	}

	Buffer buffer;
	byte[] ba4 = new byte[4];

	public Packet(final Buffer buffer) {
		this.buffer = buffer;
	}

	public void reset() {
		this.buffer.index = 5;
	}

	void padding(final int bsize) {
		int len = this.buffer.index;
		int pad = (-len) & (bsize - 1);
		if (pad < bsize) {
			pad += bsize;
		}
		len = len + pad - 4;
		this.ba4[0] = (byte) (len >>> 24);
		this.ba4[1] = (byte) (len >>> 16);
		this.ba4[2] = (byte) (len >>> 8);
		this.ba4[3] = (byte) (len);
		System.arraycopy(this.ba4, 0, this.buffer.buffer, 0, 4);
		this.buffer.buffer[4] = (byte) pad;
		synchronized (random) {
			random.fill(this.buffer.buffer, this.buffer.index, pad);
		}
		this.buffer.skip(pad);
		// buffer.putPad(pad);
		/*
		 * for(int i=0; i<buffer.index; i++){
		 * System.err.print(Integer.toHexString(buffer.buffer[i]&0xff)+":");
		 * }
		 * System.err.println("");
		 */
	}

	int shift(final int len, final int bsize, final int mac) {
		int s = len + 5 + 9;
		int pad = (-s) & (bsize - 1);
		if (pad < bsize) {
			pad += bsize;
		}
		s += pad;
		s += mac;
		s += 32; // margin for deflater; deflater may inflate data

		/**/
		if (this.buffer.buffer.length < s + this.buffer.index - 5 - 9 - len) {
			final byte[] foo = new byte[s + this.buffer.index - 5 - 9 - len];
			System.arraycopy(this.buffer.buffer, 0, foo, 0, this.buffer.buffer.length);
			this.buffer.buffer = foo;
		}
		/**/

		// if(buffer.buffer.length<len+5+9)
		// System.err.println("buffer.buffer.length="+buffer.buffer.length+" len+5+9="+(len+5+9));

		// if(buffer.buffer.length<s)
		// System.err.println("buffer.buffer.length="+buffer.buffer.length+" s="+(s));

		System.arraycopy(this.buffer.buffer,
				len + 5 + 9,
				this.buffer.buffer, s, this.buffer.index - 5 - 9 - len);

		this.buffer.index = 10;
		this.buffer.putInt(len);
		this.buffer.index = len + 5 + 9;
		return s;
	}

	void unshift(final byte command, final int recipient, final int s, final int len) {
		System.arraycopy(this.buffer.buffer,
				s,
				this.buffer.buffer, 5 + 9, len);
		this.buffer.buffer[5] = command;
		this.buffer.index = 6;
		this.buffer.putInt(recipient);
		this.buffer.putInt(len);
		this.buffer.index = len + 5 + 9;
	}

	Buffer getBuffer() {
		return this.buffer;
	}
}
