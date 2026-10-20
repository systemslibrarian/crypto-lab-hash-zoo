/// <reference types="node" />
import { expect, it } from 'vitest';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { aesEncryptBlock,aesDecryptBlock,daviesMeyer,noFeedForward,preimageNoFF,fixedPoint,mdHash,padZeroFill,padKL63,parseBlock,hex } from './dm';
const b=(s:string)=>Uint8Array.from(Buffer.from(s,'hex'));
const key=b('2b7e151628aed2a6abf7158809cf4f3c');
const published=[
 ['6bc1bee22e409f96e93d7e117393172a','3ad77bb40d7a3660a89ecaf32466ef97'],
 ['ae2d8a571e03ac9c9eb76fac45af8e51','f5d3d58503b9699de785895a96fdbaaf'],
 ['30c81c46a35ce411e5fbc1191a0a52ef','43b1cd7f598ece23881b00e3ed030688'],
 ['f69f2445df4f9b17ad2b417be66c3710','7b0c785e27e8ad3f8223207104725dd4'],
];
it.each(published)('NIST SP 800-38A F.1.1/F.1.2 AES-128 block %s encrypts and decrypts',(p,c)=>{
 expect(hex(aesEncryptBlock(key,b(p)))).toBe(c);expect(hex(aesDecryptBlock(key,b(c)))).toBe(p);
});
it('all four published blocks form the complete 64-byte AES-ECB example',()=>{
 const cipher=createCipheriv('aes-128-ecb',key,null);cipher.setAutoPadding(false);
 expect(Buffer.concat([cipher.update(Buffer.from(published.map(x=>x[0]).join(''),'hex')),cipher.final()]).toString('hex')).toBe(published.map(x=>x[1]).join(''));
 expect(published.map(([p])=>hex(aesEncryptBlock(key,b(p)))).join('')).toBe(published.map(x=>x[1]).join(''));
});
it('round trips fixed points and free-start preimages agree with independent OpenSSL',()=>{
 for(let i=0;i<300;i++){
  const k=randomBytes(16),x=randomBytes(16),y=randomBytes(16);
  const oracle=createCipheriv('aes-128-ecb',k,null);oracle.setAutoPadding(false);const encrypted=Buffer.concat([oracle.update(x),oracle.final()]);
  expect(aesEncryptBlock(k,x)).toEqual(new Uint8Array(encrypted));expect(aesDecryptBlock(k,encrypted)).toEqual(new Uint8Array(x));
  const point=fixedPoint(k);expect(daviesMeyer(k,point)).toEqual(point);expect(aesEncryptBlock(k,point)).toEqual(new Uint8Array(16));
  const preimage=preimageNoFF(k,y);expect(noFeedForward(k,preimage)).toEqual(new Uint8Array(y));expect(daviesMeyer(k,preimage)).not.toEqual(new Uint8Array(y));
  const inverse=createDecipheriv('aes-128-ecb',k,null);inverse.setAutoPadding(false);expect(preimage).toEqual(new Uint8Array(Buffer.concat([inverse.update(y),inverse.final()])));
 }
 // Algebraic exception, not random luck: x=0 cancels no bits in feed-forward.
 const y=aesEncryptBlock(key,new Uint8Array(16));expect(daviesMeyer(key,preimageNoFF(key,y))).toEqual(y);
});
it('both paddings obey their boundary rules and Construction 6.3 stores the actual bit length',()=>{
 for(let length=0;length<=1024;length++){
  const m=randomBytes(length),p=padKL63(m);expect(p.length%16).toBe(0);expect(p[length]).toBe(128);expect(p.slice(0,length)).toEqual(new Uint8Array(m));
  expect(new DataView(p.buffer).getBigUint64(p.length-8,false)).toBe(BigInt(length)*8n);
  expect([...p.slice(length+1,p.length-8)].every(x=>x===0)).toBe(true);
  if(length%16!==0)expect(padZeroFill(m)).toEqual(padZeroFill(Buffer.concat([m,Buffer.from([0])])));
 }
 expect(padZeroFill(new Uint8Array())).toHaveLength(0);expect(padZeroFill(new Uint8Array(16))).toHaveLength(16);expect(padZeroFill(new Uint8Array(17))).toHaveLength(32);
});
it('independent MD chain and every recorded compression agree for both padding modes',()=>{
 for(const padding of ['kl-6.3','zero-fill'] as const)for(let length=0;length<100;length++){
  const m=randomBytes(length),iv=randomBytes(16),p=Array.from(m);if(padding==='kl-6.3'){p.push(128);while(p.length%16!==8)p.push(0);for(let shift=56n;shift>=0n;shift-=8n)p.push(Number((BigInt(length)*8n>>shift)&255n));}else while(p.length%16)p.push(0);
  let state=Buffer.from(iv);const out=mdHash(m,{padding,iv});expect(Array.from(out.padded)).toEqual(p);
  for(let i=0;i<p.length;i+=16){const k=Buffer.from(p.slice(i,i+16)),cipher=createCipheriv('aes-128-ecb',k,null);cipher.setAutoPadding(false);const encrypted=Buffer.concat([cipher.update(state),cipher.final()]);
   expect(out.blocks[i/16].input).toEqual(new Uint8Array(state));expect(out.blocks[i/16].encrypted).toEqual(new Uint8Array(encrypted));state=Buffer.from(state.map((x,j)=>x^encrypted[j]));expect(out.blocks[i/16].output).toEqual(new Uint8Array(state));}
  expect(out.digest).toEqual(new Uint8Array(state));
 }
});
it('chosen-IV repetitions collide only in the zero-fill experiment for the fixed fixture',()=>{
 const iv=fixedPoint(key);const result=(padding:'zero-fill'|'kl-6.3')=>[1,2,3].map(n=>hex(mdHash(Buffer.concat(Array(n).fill(key)),{iv,padding}).digest));
 expect(new Set(result('zero-fill')).size).toBe(1);expect(new Set(result('kl-6.3')).size).toBe(3);
});
it('parsing names invalid characters and actual UTF-8 lengths; the core refuses bad blocks',()=>{
 expect(()=>parseBlock('abz','Message block')).toThrow('position 3');expect(()=>parseBlock('abc','Message block')).toThrow('1.5 bytes');
 expect(()=>parseBlock('é'.repeat(9),'Message block','text')).toThrow('received 18');expect(parseBlock('é'.repeat(8),'Message block','text')).toHaveLength(16);
 expect(()=>aesEncryptBlock(new Uint8Array(15),new Uint8Array(16))).toThrow('received 15');expect(()=>mdHash(new Uint8Array(65537),{padding:'kl-6.3'})).toThrow('65,536');
});
