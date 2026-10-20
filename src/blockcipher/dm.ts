import { ecb } from '@noble/ciphers/aes.js';

export type Padding='zero-fill'|'kl-6.3';
export interface BlockTrace {message:Uint8Array;input:Uint8Array;encrypted:Uint8Array;output:Uint8Array}
export interface MDResult {digest:Uint8Array;padded:Uint8Array;blocks:BlockTrace[]}
export const FIXED_IV=new Uint8Array(16);
export const equalBytes=(a:Uint8Array,b:Uint8Array):boolean=>a.length===b.length&&a.every((v,i)=>v===b[i]);
export const hex=(a:Uint8Array):string=>Array.from(a,x=>x.toString(16).padStart(2,'0')).join('');
function block(value:Uint8Array,label:string):void{if(value.length!==16)throw new Error(`${label} must be exactly 16 bytes; received ${value.length}.`);}
export function parseBlock(value:string,label:string,format:'hex'|'text'='hex'):Uint8Array {
  if(format==='text'){const out=new TextEncoder().encode(value);block(out,label);return out;}
  // No trimming or filtering: an invalid character is reported at its actual position.
  const bad=value.search(/[^0-9a-f]/i);if(bad!==-1)throw new Error(`${label}: non-hex character at position ${bad+1}.`);
  if(value.length%2)throw new Error(`${label}: incomplete byte at position ${value.length}; received ${value.length/2} bytes.`);
  const out=Uint8Array.from(value.match(/../g)??[],x=>parseInt(x,16));block(out,label);return out;
}
export function aesEncryptBlock(k:Uint8Array,x:Uint8Array):Uint8Array{block(k,'Message block / AES key');block(x,'AES input');return ecb(k,{disablePadding:true}).encrypt(x);}
export function aesDecryptBlock(k:Uint8Array,y:Uint8Array):Uint8Array{block(k,'Message block / AES key');block(y,'AES target');return ecb(k,{disablePadding:true}).decrypt(y);}
export function xor(a:Uint8Array,b:Uint8Array):Uint8Array{block(a,'XOR input');block(b,'XOR input');return Uint8Array.from(a,(v,i)=>v^b[i]);}
// [extension] point: Matyas–Meyer–Oseas and Miyaguchi–Preneel change this wiring.
function compression(k:Uint8Array,x:Uint8Array):BlockTrace{const encrypted=aesEncryptBlock(k,x);return {message:new Uint8Array(k),input:new Uint8Array(x),encrypted,output:xor(encrypted,x)};}
export function daviesMeyer(k:Uint8Array,x:Uint8Array):Uint8Array{return compression(k,x).output;}
/** Deliberately broken free-start compression: the feed-forward wire is absent. */
export function noFeedForward(k:Uint8Array,x:Uint8Array):Uint8Array{return aesEncryptBlock(k,x);}
export function preimageNoFF(k:Uint8Array,y:Uint8Array):Uint8Array{return aesDecryptBlock(k,y);}
export function fixedPoint(m:Uint8Array):Uint8Array{return aesDecryptBlock(m,new Uint8Array(16));}
export function padZeroFill(message:Uint8Array):Uint8Array{const out=new Uint8Array(Math.ceil(message.length/16)*16);out.set(message);return out;}
export function padKL63(message:Uint8Array):Uint8Array {
  const out=new Uint8Array(Math.ceil((message.length+1+8)/16)*16);out.set(message);out[message.length]=0x80;
  new DataView(out.buffer).setBigUint64(out.length-8,BigInt(message.length)*8n,false);return out;
}
export function mdHash(message:Uint8Array,{padding,iv=FIXED_IV}:{padding:Padding;iv?:Uint8Array}):MDResult {
  block(iv,'IV');if(message.length>65536)throw new Error('Teaching hash accepts at most 65,536 bytes per run.');
  // [extension] point: a later expandable-message experiment can reuse this trace.
  const padded=padding==='zero-fill'?padZeroFill(message):padding==='kl-6.3'?padKL63(message):null;
  if(!padded)throw new Error('Unknown padding mode');
  let state:Uint8Array=new Uint8Array(iv);const blocks:BlockTrace[]=[];
  for(let offset=0;offset<padded.length;offset+=16){
    const step=compression(padded.slice(offset,offset+16),state);state=step.output;
    blocks.push(step);
  }
  return {digest:state.slice(),padded,blocks};
}
