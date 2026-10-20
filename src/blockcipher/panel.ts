import { aesEncryptBlock, daviesMeyer, equalBytes, fixedPoint, FIXED_IV, hex, mdHash, noFeedForward, parseBlock, preimageNoFF, type MDResult, type Padding } from './dm';

export const DM_NEGATIVE_CLAIM='A compression function built from a sound block cipher does not make the hash collision-resistant if the padding is ambiguous.';
type Child=Node|string;
function el<K extends keyof HTMLElementTagNameMap>(tag:K,attrs:Record<string,string>={},...children:Child[]):HTMLElementTagNameMap[K]{const node=document.createElement(tag);for(const[k,v]of Object.entries(attrs))node.setAttribute(k,v);node.append(...children);return node;}
function field(id:string,label:string,value:string):{input:HTMLInputElement;wrap:HTMLElement}{const input=el('input',{id,type:'text',value,spellcheck:'false',autocomplete:'off'});return {input,wrap:el('div',{class:'dm-field'},el('label',{for:id},label),input)};}
function action(id:string,label:string):HTMLButtonElement{return el('button',{type:'button',id},label);}
function status(id:string):HTMLElement{return el('div',{id,role:'status','aria-live':'polite'});}
function verdict(tone:'alarm'|'held'|'neutral'|'error',text:string):HTMLElement{return el('p',{class:`dm-verdict dm-${tone}`,'data-verdict':tone},`${tone==='alarm'?'⚠':tone==='held'?'✓':tone==='error'?'✕':'–'} ${text}`);}
function pair(name:string,value:Uint8Array,attr:string):HTMLElement{return el('div',{class:'dm-value'},el('strong',{},name),el('code',{'data-value':attr},hex(value)));}
function scroll(label:string,...children:Child[]):HTMLElement{return el('div',{class:'dm-scroll',role:'region',tabindex:'0','aria-label':label},...children);}
function trace(result:MDResult,label:string):HTMLElement {
  const body=el('tbody');result.blocks.forEach((b,i)=>body.append(el('tr',{'data-block':String(i)},el('th',{scope:'row'},String(i+1)),...(['message','input','encrypted','output'] as const).map(name=>el('td',{},el('code',{'data-part':name},hex(b[name])))))));
  return el('details',{class:'dm-trace'},el('summary',{},`${label}: inspect ${result.blocks.length} AES calls and padded bytes`),
    pair('Padded message',result.padded,'padded'),scroll(`${label} compression trace`,el('table',{},el('thead',{},el('tr',{},...['Block','Message as key','Chaining input','AES output','XOR output'].map(name=>el('th',{scope:'col'},name)))),body)));
}
function diff(a:Uint8Array,b:Uint8Array):HTMLElement{
  const list=el('ol',{class:'dm-byte-diff','aria-label':'Digest byte comparison'});for(let i=0;i<a.length;i++)list.append(el('li',{'data-equal':String(a[i]===b[i])},`Byte ${i+1}: ${a[i].toString(16).padStart(2,'0')} / ${b[i].toString(16).padStart(2,'0')} — ${a[i]===b[i]?'same':'different'}`));return list;
}

export function mountBlockCipherSection(before:HTMLElement):void {
  const root=el('section',{class:'panel',id:'blockcipher-section'});before.before(root);
  root.append(el('h2',{},'Section D — A hash from a block cipher'),
    el('p',{},'SHA-256 feeds its working state back into its output after scrambling a message block. This section builds a small hash from AES using the same idea, then removes one wire at a time to show what each one does. A reversible cipher alone is easy to undo; the surrounding construction matters.'),
    el('p',{},'This teaching hash has a 128-bit chaining value: a generic birthday collision costs about 2⁶⁴ AES calls, so it is not a usable hash. SHA-256 has a 256-bit state and feeds it forward with word-wise addition modulo 2³², rather than this XOR.'));
  const key=field('dm-key','Message block k (also the AES-128 key)','2b7e151628aed2a6abf7158809cf4f3c');
  const format=el('select',{id:'dm-format'},el('option',{value:'hex'},'Hex bytes'),el('option',{value:'text'},'UTF-8 text'));
  const x=field('dm-x','Chaining value x (exactly 16 bytes, hex)','6bc1bee22e409f96e93d7e117393172a');
  const y=field('dm-y','Target y (exactly 16 bytes, hex)','3ad77bb40d7a3660a89ecaf32466ef97');
  const calculate=action('dm-compress','Compute compression'),find=action('dm-preimage','Find a preimage'),point=action('dm-fixed','Find a fixed point for this block'),hash=action('dm-hash','Hash m and m‖00'),chosen=action('dm-chosen','Chosen-IV fixed point');
  const compressionOut=status('dm-compression-result'),preimageOut=status('dm-preimage-result'),fixedOut=status('dm-fixed-result'),hashOut=status('dm-hash-result'),chosenOut=status('dm-chosen-result');
  const feed=el('input',{id:'dm-feed',type:'checkbox',checked:''});
  const modeNote=el('p',{id:'dm-feed-mode'},'Feed-forward ON — Davies–Meyer.');
  const message=el('textarea',{id:'dm-message',rows:'2',maxlength:'4096'},'hello');
  const kl=el('input',{id:'dm-kl',type:'radio',name:'dm-padding',value:'kl-6.3',checked:''}),zero=el('input',{id:'dm-zero',type:'radio',name:'dm-padding',value:'zero-fill'});
  const paddingNote=el('p',{id:'dm-padding-note'},'Construction 6.3 — delimiter, zeros, then a 64-bit big-endian bit length.');
  const figure=el('div',{class:'dm-figure'});
  figure.innerHTML='<svg viewBox="0 0 280 330" role="img" aria-labelledby="dm-figure-title"><title id="dm-figure-title">Chaining input x enters AES and also bypasses it to the output XOR; message k is the AES key.</title><g fill="none" stroke="currentColor" stroke-width="2"><path d="M140 35 V95 M140 55 H30 V225 H115 M140 160 V200 M140 250 V300 M235 85 V127 H205"/><rect x="75" y="95" width="130" height="65" rx="8"/><circle cx="140" cy="225" r="25"/><path d="M130 225 H150 M140 215 V235 M135 85 L140 95 L145 85 M135 190 L140 200 L145 190 M105 220 L115 225 L105 230 M135 290 L140 300 L145 290 M215 122 L205 127 L215 132"/></g><g fill="currentColor" font-size="17" text-anchor="middle"><text x="140" y="24">Chaining input x</text><text x="226" y="75">Key k</text><text x="140" y="133">AES-128</text><text x="195" y="187">Fₖ(x)</text><text x="140" y="323">Output h(k,x)</text><text x="19" y="180">x</text></g></svg>';
  root.append(el('div',{class:'dm-card'},el('h3',{},'1. Wire the chaining input back in'),
    el('p',{},'The message block is the cipher key; the chaining value is the cipher input. Two 128-bit inputs become one 128-bit output: 256 bits in, 128 bits out.'),
    el('div',{class:'dm-fields'},el('div',{class:'dm-field'},el('label',{for:'dm-format'},'Message-block format'),format),key.wrap,x.wrap),figure,calculate,compressionOut),
    el('div',{class:'dm-card'},el('h3',{},'2. Remove the feed-forward wire'),el('label',{class:'dm-choice',for:'dm-feed'},feed,'Feed-forward XOR enabled'),modeNote,
      el('p',{},'Free-start experiment: the attacker chooses the chaining value too. A fixed-IV hash does not allow that choice for its first block.'),y.wrap,find,preimageOut),
    el('div',{class:'dm-card'},el('h3',{},'3. Find a fixed point'),el('p',{},'Decrypt an all-zero block using the current message block as the key. At that input, the AES output is zero, so feed-forward returns the input unchanged.'),point,fixedOut,
      el('p',{},'This does not reach the fixed point from a prescribed IV. In the idealized 128-bit model, reaching a specified state by a generic preimage search costs about 2¹²⁸ work. Long-message second-preimage attacks use expandable messages; this page does not execute those attacks.'),
      el('a',{href:'https://www.schneier.com/academic/archives/2005/01/second_preimages_on.html'},'Kelsey–Schneier, EUROCRYPT 2005: expandable messages')),
    el('div',{class:'dm-card'},el('h3',{},'4. Chain blocks, then preserve the length'),
      el('label',{for:'dm-message'},'Message m (UTF-8; at most 4,096 bytes)'),message,
      el('fieldset',{},el('legend',{},'Padding for the message pair'),el('label',{class:'dm-choice',for:'dm-kl'},kl,'Construction 6.3 (default)'),el('label',{class:'dm-choice',for:'dm-zero'},zero,'Zero-fill only (deliberately broken)')),paddingNote,
      pair('Constant IV for this message pair',FIXED_IV,'constant-iv'),hash,hashOut,
      el('details',{},el('summary',{},'Why the length block matters'),el('p',{},'Different bit lengths produce different final length fields, so the final padded blocks differ. In the collision-resistance reduction, a hash collision between those lengths would therefore expose a compression collision; padding alone does not prove this particular teaching hash secure.')),
      el('p',{},'The separate chosen-IV experiment below sets the IV to the fixed point of the current 16-byte message block k, then hashes k, k‖k and k‖k‖k under both padding rules. A real hash fixes its IV; this deliberately chosen IV shows what a length field buys even in that artificial setting.'),chosen,chosenOut),
    el('p',{class:'mini-note'},'AES-128: @noble/ciphers, raw single-block ECB with library padding disabled. Known answers: ',el('a',{href:'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf'},'NIST SP 800-38A, F.1.1–F.1.2, all four blocks'),'. SHA-256 feed-forward: ',el('a',{href:'https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf'},'FIPS 180-4 §6.2.2, step 4'),'. Davies–Meyer and the length encoding: Katz–Lindell, third edition, §7.3.1 and Construction 6.3. These are computed experiments, not published AES-based hash vectors.'));
  const outputs=[compressionOut,preimageOut,fixedOut,hashOut,chosenOut];
  const fingerprint=()=>JSON.stringify([key.input.value,format.value,x.input.value,y.input.value,message.value,feed.checked,zero.checked]);let previous=fingerprint();
  function retire():void {const next=fingerprint();if(next===previous)return;previous=next;for(const out of outputs)if(out.childNodes.length)out.replaceChildren(el('p',{class:'dm-retired'},'Result retired: inputs changed. Run this step again.'));modeNote.textContent=feed.checked?'Feed-forward ON — Davies–Meyer.':'BROKEN VARIANT — no feed-forward; AES is invertible.';paddingNote.textContent=zero.checked?'BROKEN VARIANT — zero-fill only, no delimiter or length.':'Construction 6.3 — delimiter, zeros, then a 64-bit big-endian bit length.';}
  for(const input of [key.input,format,x.input,y.input,message,feed,kl,zero]){input.addEventListener('input',retire);input.addEventListener('change',retire);}
  const k=()=>parseBlock(key.input.value,'Message block k',format.value as 'hex'|'text');
  const execute=(out:HTMLElement,fn:()=>void)=>{out.replaceChildren();try{fn();}catch(error){out.replaceChildren(verdict('error',error instanceof Error?error.message:String(error)));}};
  calculate.addEventListener('click',()=>execute(compressionOut,()=>{const key=k(),input=parseBlock(x.input.value,'Chaining value x'),encrypted=aesEncryptBlock(key,input),output=daviesMeyer(key,input);compressionOut.append(pair('Message as AES key',key,'key'),pair('F_k(x)',encrypted,'cipher'),pair('Feed-forward x',input,'x'),pair('h(k,x) = F_k(x) XOR x',output,'output'),verdict('neutral','Compression computed: 256 input bits → 128 output bits.'));}));
  find.addEventListener('click',()=>execute(preimageOut,()=>{const key=k(),target=parseBlock(y.input.value,'Target y'),input=preimageNoFF(key,target),cipher=noFeedForward(key,input),output=feed.checked?daviesMeyer(key,input):cipher,hit=equalBytes(output,target);
    preimageOut.append(pair('Message as AES key',key,'key'),pair('x = AES decrypt of y',input,'x'),pair('Re-encrypted AES output',cipher,'cipher'),pair('Target y',target,'target'),pair('Recomputed compression',output,'output'),
      verdict(!feed.checked&&hit?'alarm':hit?'neutral':'held',!feed.checked&&hit?'FREE-START PREIMAGE FOUND — one AES decryption.':hit?'ZERO-INPUT EXCEPTION — x is all zero, so XOR changes nothing; this target is still hit.':'HELD — decryption alone did not invert Davies–Meyer for this target.'),
      el('p',{},'With feed-forward, the unknown x appears both inside AES and outside it. The simple inverse trick is not a general inversion method; x = 0 is a real special case.'));
  }));
  point.addEventListener('click',()=>execute(fixedOut,()=>{const key=k(),p=fixedPoint(key),encrypted=aesEncryptBlock(key,p),output=daviesMeyer(key,p),holds=equalBytes(p,output)&&encrypted.every(x=>x===0);fixedOut.append(pair('Message as AES key',key,'key'),pair('x*',p,'point'),pair('AES_m(x*)',encrypted,'cipher'),pair('h(m,x*)',output,'output'),verdict(holds?'neutral':'error',holds?'FIXED POINT — a fixed point exists; reaching it from a fixed IV is the hard part.':'Fixed-point identity failed.'));}));
  hash.addEventListener('click',()=>execute(hashOut,()=>{
    const m=new TextEncoder().encode(message.value);if(!m.length)throw new Error('Empty message: refuse to claim a collision. Zero-fill needs a non-empty partial block.');if(m.length>4096)throw new Error(`Message limit is 4,096 UTF-8 bytes; received ${m.length}.`);
    const extended=new Uint8Array(m.length+1);extended.set(m);const padding:Padding=zero.checked?'zero-fill':'kl-6.3',a=mdHash(m,{padding}),b=mdHash(extended,{padding}),collision=equalBytes(a.digest,b.digest);
    hashOut.append(pair('Message bytes m',m,'message'),pair('Message bytes m‖00',extended,'extended'),pair('H(m)',a.digest,'digest-a'),pair('H(m‖00)',b.digest,'digest-b'),
      verdict(collision?'alarm':'held',collision?'EVERY BLOCK CORRECT — AND COLLIDING':padding==='kl-6.3'?'HELD — lengths differ, last blocks differ; these digests differ.':'NO COLLISION — the appended zero adds a whole block; try a non-aligned message length.'),
      el('p',{},`${m.length} bytes → ${a.blocks.length} AES calls; ${extended.length} bytes → ${b.blocks.length} AES calls.`),diff(a.digest,b.digest),trace(a,'m'),trace(b,'m‖00'));
    if(collision&&padding==='zero-fill')hashOut.append(el('p',{'data-claim':'NEG-DM'},DM_NEGATIVE_CLAIM));
    if(padding==='zero-fill'&&m.length%16===0)hashOut.append(el('p',{},'The original message was block-aligned, so zero-fill leaves it alone while the appended byte needs another block. This pair is outside the partial-block collision fixture.'));
  }));
  chosen.addEventListener('click',()=>execute(chosenOut,()=>{
    const key=k(),iv=fixedPoint(key);chosenOut.append(pair('Chosen IV = x* for k',iv,'chosen-iv'),pair('Repeated 16-byte message block',key,'key'));
    for(const padding of ['zero-fill','kl-6.3'] as const){
      const box=el('div',{'data-padding':padding}),results=[1,2,3].map(n=>{const m=new Uint8Array(16*n);for(let i=0;i<n;i++)m.set(key,16*i);return mdHash(m,{padding,iv});});
      const distinct=new Set(results.map(r=>hex(r.digest))).size;
      box.append(el('h4',{},padding==='zero-fill'?'Zero-fill, chosen IV':'Construction 6.3, chosen IV'),verdict(distinct===3?'held':'alarm',`CHOSEN IV — ${distinct} distinct digest${distinct===1?'':'s'} from 1, 2 and 3 repetitions. ${padding==='zero-fill'?'The fixed point can repeat without recording the length.':'The length fields record 128, 256 and 384 bits.'}`));
      results.forEach((r,i)=>box.append(pair(`H(k repeated ${i+1} times)`,r.digest,`repeat-${i+1}`),trace(r,`${padding}, ${i+1} repetition${i?'s':''}`)));chosenOut.append(box);
    }
  }));
}
