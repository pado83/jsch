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
import javax.crypto.*;
import javax.crypto.spec.*;
import com.jcraft.jsch.JSchException;

public class DH implements com.jcraft.jsch.DH{
  BigInteger p;
  BigInteger g;
  BigInteger e;  // my public key
  byte[] e_array;
  BigInteger f;  // your public key
  BigInteger K;  // shared secret key
  byte[] K_array;

  private KeyPairGenerator myKpairGen;
  private KeyAgreement myKeyAgree;
  @Override
public void init() throws Exception{
    this.myKpairGen=KeyPairGenerator.getInstance("DH");
    this.myKeyAgree=KeyAgreement.getInstance("DH");
  }
  @Override
public byte[] getE() throws Exception{
    if(this.e==null){
      DHParameterSpec dhSkipParamSpec=new DHParameterSpec(this.p, this.g);
      this.myKpairGen.initialize(dhSkipParamSpec);
      KeyPair myKpair=this.myKpairGen.generateKeyPair();
      this.myKeyAgree.init(myKpair.getPrivate());
      this.e=((javax.crypto.interfaces.DHPublicKey)(myKpair.getPublic())).getY();
      this.e_array=this.e.toByteArray();
    }
    return this.e_array;
  }
  @Override
public byte[] getK() throws Exception{
    if(this.K==null){
      KeyFactory myKeyFac=KeyFactory.getInstance("DH");
      DHPublicKeySpec keySpec=new DHPublicKeySpec(this.f, this.p, this.g);
      PublicKey yourPubKey=myKeyFac.generatePublic(keySpec);
      this.myKeyAgree.doPhase(yourPubKey, true);
      byte[] mySharedSecret=this.myKeyAgree.generateSecret();
      this.K=new BigInteger(1, mySharedSecret);
      this.K_array=this.K.toByteArray();
      this.K_array=mySharedSecret;
    }
    return this.K_array;
  }
  @Override
public void setP(byte[] p){ setP(new BigInteger(1, p)); }
  @Override
public void setG(byte[] g){ setG(new BigInteger(1, g)); }
  @Override
public void setF(byte[] f){ setF(new BigInteger(1, f)); }
  void setP(BigInteger p){this.p=p;}
  void setG(BigInteger g){this.g=g;}
  void setF(BigInteger f){this.f=f;}

  // e, f must be in [1, p-1].
  @Override
public void checkRange() throws Exception {
    /*
    checkRange(e);
    checkRange(f);
    */
  }

  private void checkRange(BigInteger tmp) throws Exception {
    BigInteger one = BigInteger.ONE;
    BigInteger p_1 = this.p.subtract(one);
    // !(1<tmp && tmp<p-1)  We expect tmp is in the range [2, p-2].
    if(!(one.compareTo(tmp) < 0 && tmp.compareTo(p_1) < 0)){
      throw new JSchException("invalid DH value");
   }
  }
}
