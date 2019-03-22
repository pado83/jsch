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

package com.jcraft.jsch.jce;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import com.jcraft.jsch.Buffer;

public class SignatureRSA implements com.jcraft.jsch.SignatureRSA{

  java.security.Signature signature;
  KeyFactory keyFactory;

  @Override
public void init() throws Exception{
    this.signature=java.security.Signature.getInstance("SHA1withRSA");
    this.keyFactory=KeyFactory.getInstance("RSA");
  }     
  @Override
public void setPubKey(byte[] e, byte[] n) throws Exception{
    RSAPublicKeySpec rsaPubKeySpec = 
	new RSAPublicKeySpec(new BigInteger(n),
			     new BigInteger(e));
    PublicKey pubKey=this.keyFactory.generatePublic(rsaPubKeySpec);
    this.signature.initVerify(pubKey);
  }
  @Override
public void setPrvKey(byte[] d, byte[] n) throws Exception{
    RSAPrivateKeySpec rsaPrivKeySpec = 
	new RSAPrivateKeySpec(new BigInteger(n),
			      new BigInteger(d));
    PrivateKey prvKey = this.keyFactory.generatePrivate(rsaPrivKeySpec);
    this.signature.initSign(prvKey);
  }
  @Override
public byte[] sign() throws Exception{
    byte[] sig=this.signature.sign();      
    return sig;
  }
  @Override
public void update(byte[] foo) throws Exception{
   this.signature.update(foo);
  }
  @Override
public boolean verify(byte[] sig) throws Exception{
    int i=0;
    int j=0;
    byte[] tmp;
    Buffer buf=new Buffer(sig);

    if(new String(buf.getString()).equals("ssh-rsa")){
      j=buf.getInt();
      i=buf.getOffSet();
      tmp=new byte[j];
      System.arraycopy(sig, i, tmp, 0, j); sig=tmp;
    }

    return this.signature.verify(sig);
  }
}
