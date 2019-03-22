/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2012-2018 ymnk, JCraft,Inc. All rights reserved.

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

package com.jcraft.jsch.jce;

import com.jcraft.jsch.MAC;
import javax.crypto.*;
import javax.crypto.spec.*;

abstract class HMAC implements MAC {
  protected String name;
  protected int bsize;
  protected String algorithm;
  private Mac mac;

  @Override
public int getBlockSize() {
    return this.bsize;
  };

  @Override
public void init(byte[] key) throws Exception {
    if(key.length>this.bsize){
      byte[] tmp = new byte[this.bsize];
      System.arraycopy(key, 0, tmp, 0, this.bsize);	  
      key = tmp;
    }
    SecretKeySpec skey = new SecretKeySpec(key, this.algorithm);
    this.mac = Mac.getInstance(this.algorithm);
    this.mac.init(skey);
  } 

  private final byte[] tmp = new byte[4];
  @Override
public void update(int i){
    this.tmp[0] = (byte)(i>>>24);
    this.tmp[1] = (byte)(i>>>16);
    this.tmp[2] = (byte)(i>>>8);
    this.tmp[3] = (byte)i;
    update(this.tmp, 0, 4);
  }

  @Override
public void update(byte foo[], int s, int l){
    this.mac.update(foo, s, l);      
  }

  @Override
public void doFinal(byte[] buf, int offset){
    try{
      this.mac.doFinal(buf, offset);
    }
    catch(ShortBufferException e){
      System.err.println(e);
    }
  }

  @Override
public String getName(){
    return this.name;
  }
}
