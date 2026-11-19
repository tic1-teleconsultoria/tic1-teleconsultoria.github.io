/*
 * TIC1 — núcleo que faz, no navegador, o papel que antes era do servidor.
 *
 * Os dados ficam num repositório privado do GitHub (tic1-dados) como comentários de issues,
 * sempre cifrados (AES-256-GCM) e assinados (ECDSA P-256). Cada navegador lê o registro de
 * eventos, decifra o que lhe cabe (RN19 por criptografia) e recalcula o estado aplicando as
 * mesmas regras, na ordem que o GitHub atribui. O mesmo arquivo roda no Node (testes e
 * ferramenta de administração).
 */
(function (raiz, fabrica) {
  const N = fabrica();
  if (typeof module === 'object' && module.exports) module.exports = N;
  else raiz.TIC1Nucleo = N;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const VERSAO = '1.0.0';
  const ESQUEMA = 1;
  const REGRAS = 1;
  const FUSO = 'America/Sao_Paulo';
  const ITER_PADRAO = 600000;
  const MAX_CORPO = 60000;
  const MAX_ANEXO = 15 * 1024 * 1024;
  const MAX_ANEXOS = 40 * 1024 * 1024;
  const SESSAO_MS = 12 * 3600 * 1000;
  const COORD = '_coord';

  const cr = globalThis.crypto;
  const sutil = cr.subtle;
  const codif = new TextEncoder();
  const decod = new TextDecoder();
  const NO_NAVEGADOR = typeof window !== 'undefined' && typeof document !== 'undefined';

  // ---------------------------------------------------------------- bytes

  function bytes(x) {
    if (typeof x === 'string') return codif.encode(x);
    if (x instanceof Uint8Array) return x;
    return new Uint8Array(x);
  }
  function b64(u8) {
    let s = '';
    for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    return btoa(s);
  }
  function deb64(s) {
    const bin = atob(String(s).replace(/\s+/g, ''));
    const u = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }
  function b64u(u8) { return b64(u8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function deb64u(s) {
    s = String(s).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    return deb64(s);
  }
  function aleatorio(n) { const u = new Uint8Array(n); cr.getRandomValues(u); return u; }
  const ALFA = 'abcdefghijkmnpqrstuvwxyz23456789';
  function idAleatorio(n) {
    const r = aleatorio(n || 12);
    let s = '';
    for (const x of r) s += ALFA[x & 31];
    return s;
  }
  function hex(u8) { return Array.from(u8, b => b.toString(16).padStart(2, '0')).join(''); }
  function concat() {
    const a = Array.from(arguments);
    const o = new Uint8Array(a.reduce((s, x) => s + x.length, 0));
    let p = 0;
    for (const x of a) { o.set(x, p); p += x.length; }
    return o;
  }
  async function sha256(x) { return new Uint8Array(await sutil.digest('SHA-256', bytes(x))); }
  function canon(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    const ks = Object.keys(v).filter(k => v[k] !== undefined).sort();
    return '{' + ks.map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  function erro(codigo, msg) { const e = new Error(msg); e.codigo = codigo; return e; }
  function copia(o) { return JSON.parse(JSON.stringify(o)); }

  // ---------------------------------------------------------------- chave secreta (Kit de acesso)

  const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  function b32(u8) {
    let bits = 0, val = 0, out = '';
    for (const b of u8) {
      val = ((val << 8) | b) & 0xffff; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }
  function deb32(s, nBytes) {
    let bits = 0, val = 0;
    const out = [];
    for (const ch of s) {
      const i = B32.indexOf(ch);
      if (i < 0) throw erro('kit-invalido', 'Chave secreta inválida.');
      val = ((val << 5) | i) & 0xffff; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    if (out.length < nBytes) throw erro('kit-invalido', 'Chave secreta incompleta.');
    return new Uint8Array(out.slice(0, nBytes));
  }
  function somaKit(u8) { let s = 7; for (const b of u8) s = (s * 31 + b) % 1024; return B32[s >> 5] + B32[s & 31]; }
  function formatarKit(u8) {
    const corpo = b32(u8) + somaKit(u8);
    return 'A1-' + corpo.match(/.{1,4}/g).join('-');
  }
  function chaveSecretaNova() { return formatarKit(aleatorio(16)); }
  function lerChaveSecreta(txt) {
    let s = String(txt || '').toUpperCase().replace(/[^0-9A-Z]/g, '');
    if (s.startsWith('A1')) s = s.slice(2);
    s = s.replace(/[IL]/g, '1').replace(/O/g, '0').replace(/U/g, 'V');
    if (s.length !== 28) throw erro('kit-invalido', 'A chave secreta tem 28 caracteres depois de "A1". Confira o seu Kit de acesso.');
    const u8 = deb32(s.slice(0, 26), 16);
    if (somaKit(u8) !== s.slice(26)) throw erro('kit-invalido', 'A chave secreta tem um erro de digitação. Confira o seu Kit de acesso.');
    return u8;
  }
  function normalizarKit(txt) { return formatarKit(lerChaveSecreta(txt)); }

  // ---------------------------------------------------------------- chaves

  const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  async function gerarIdentidade() {
    const ass = await sutil.generateKey(ECDSA, true, ['sign', 'verify']);
    const cif = await sutil.generateKey(ECDH, true, ['deriveBits']);
    return { assPriv: ass.privateKey, assPub: ass.publicKey, cifPriv: cif.privateKey, cifPub: cif.publicKey };
  }
  async function pubRaw(k) { return b64u(new Uint8Array(await sutil.exportKey('raw', k))); }
  function importarPubAss(s) { return sutil.importKey('raw', deb64u(s), ECDSA, true, ['verify']); }
  function importarPubCif(s) { return sutil.importKey('raw', deb64u(s), ECDH, true, []); }
  async function privPkcs8(k) { return b64u(new Uint8Array(await sutil.exportKey('pkcs8', k))); }
  function importarPrivAss(s, extr) { return sutil.importKey('pkcs8', deb64u(s), ECDSA, !!extr, ['sign']); }
  function importarPrivCif(s, extr) { return sutil.importKey('pkcs8', deb64u(s), ECDH, !!extr, ['deriveBits']); }
  async function pubDaPriv(priv) {
    const j = await sutil.exportKey('jwk', priv);
    return b64u(concat(new Uint8Array([4]), deb64u(j.x), deb64u(j.y)));
  }
  async function impressao(assPub, cifPub) {
    const h = await sha256(String(assPub) + '|' + String(cifPub));
    return b32(h.subarray(0, 5)).match(/.{1,4}/g).join('-');
  }

  // ---------------------------------------------------------------- cofre (senha + chave secreta)

  async function chaveSenha(login, senha, sal, iter) {
    const base = await sutil.importKey('raw', codif.encode(String(senha).normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const salP = await sha256(concat(codif.encode('tic1-cofre|' + login + '|'), sal));
    return new Uint8Array(await sutil.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: salP, iterations: iter }, base, 256));
  }
  async function hkdf(segredo, sal, info) {
    const hk = await sutil.importKey('raw', segredo, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await sutil.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: sal, info: codif.encode(info) }, hk, 256));
  }
  // Cofre v1 (só leitura, compatibilidade): senha XOR chave secreta.
  async function chaveCofreV1(login, senha, kit, sal, iter) {
    const kp = await chaveSenha(login, senha, sal, iter);
    const ks = await hkdf(kit, sal, 'tic1-chave-secreta|' + login);
    for (let i = 0; i < 32; i++) kp[i] ^= ks[i];
    return sutil.importKey('raw', kp, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  // Cofre v2: o conteúdo abre com a senha + o segredo-mestre (fm). O fm fica guardado em "fechaduras":
  // uma do Kit de acesso e uma para cada passkey. Trocar a senha não mexe nas fechaduras.
  async function chaveConteudo(login, senha, fm, sal, iter) {
    const kp = await chaveSenha(login, senha, sal, iter);
    for (let i = 0; i < 32; i++) kp[i] ^= fm[i];
    return aesImportar(await hkdf(kp, sal, 'tic1-cofre-v2|' + login));
  }
  async function chaveFechadura(segredo, s, tipo, login) { return aesImportar(await hkdf(segredo, s, 'tic1-fechadura|' + tipo + '|' + login)); }
  async function fechadura(tipo, segredo, fm, login, extra) {
    const s = aleatorio(16);
    const r = await aesCifrar(await chaveFechadura(segredo, s, tipo, login), fm, 'tic1-fm|' + tipo + '|' + login);
    return Object.assign({ t: tipo, s: b64u(s), iv: b64u(r.iv), w: b64u(r.ct) }, extra || {});
  }
  async function abrirFechadura(f, segredo, login) {
    try { return await aesDecifrar(await chaveFechadura(segredo, deb64u(f.s), f.t, login), deb64u(f.iv), deb64u(f.w), 'tic1-fm|' + f.t + '|' + login); }
    catch (e) { return null; }
  }
  async function fecharCofreFm(o) {
    const iter = o.iter || ITER_PADRAO;
    const fm = o.fm || aleatorio(32);
    const sal = aleatorio(16), iv = aleatorio(12);
    const ass = o.assPkcs8 || await privPkcs8(o.assPriv), cif = o.cifPkcs8 || await privPkcs8(o.cifPriv);
    const k = await chaveConteudo(o.login, o.senha, fm, sal, iter);
    const ct = new Uint8Array(await sutil.encrypt({ name: 'AES-GCM', iv, additionalData: codif.encode('tic1-cofre-v2|' + o.login) }, k, codif.encode(canon({ v: 2, login: o.login, ass, cif }))));
    let f = (o.fechaduras || []).slice();
    if (o.kit) { f = f.filter(x => x.t !== 'kit'); f.unshift(await fechadura('kit', o.kit, fm, o.login)); }
    return { cofre: { v: 2, sal: b64u(sal), iter, iv: b64u(iv), ct: b64u(ct), f, em: o.em || new Date().toISOString() }, fm };
  }
  async function fecharCofre(o) { return (await fecharCofreFm(o)).cofre; }
  // fator: Uint8Array (Kit) | {tipo:'kit', segredo} | {tipo:'passkey', id, segredo}
  async function abrirCofre(cofre, login, senha, fator, extr) {
    if (!cofre || !cofre.ct || !fator) return null;
    if (fator instanceof Uint8Array) fator = { tipo: 'kit', segredo: fator };
    let k, aad, fm = null;
    if (cofre.v === 2) {
      for (const f of (cofre.f || [])) {
        if (f.t !== fator.tipo || (fator.tipo === 'passkey' && f.id !== fator.id)) continue;
        fm = await abrirFechadura(f, fator.segredo, login);
        if (fm) break;
      }
      if (!fm) return null;
      k = await chaveConteudo(login, senha, fm, deb64u(cofre.sal), cofre.iter); aad = 'tic1-cofre-v2|' + login;
    } else {
      if (fator.tipo !== 'kit') return null;
      k = await chaveCofreV1(login, senha, fator.segredo, deb64u(cofre.sal), cofre.iter); aad = 'tic1-cofre-v1|' + login;
    }
    let pt;
    try { pt = await sutil.decrypt({ name: 'AES-GCM', iv: deb64u(cofre.iv), additionalData: codif.encode(aad) }, k, deb64u(cofre.ct)); }
    catch (e) { return null; }
    const o = JSON.parse(decod.decode(pt));
    if (o.login !== login) return null;
    return { assPkcs8: o.ass, cifPkcs8: o.cif, assPriv: await importarPrivAss(o.ass, extr), cifPriv: await importarPrivCif(o.cif, extr), fm };
  }
  function passkeysDoCofre(cofre) { return ((cofre && cofre.f) || []).filter(f => f.t === 'passkey').map(f => ({ id: f.id, prf: f.prf, nome: f.nome })); }

  // ---------------------------------------------------------------- passkey (WebAuthn com PRF): segundo fator sem servidor
  // O navegador oferece usar a passkey deste aparelho ou a do celular (mostra um QR code). A extensão PRF
  // devolve um segredo fixo daquela passkey, que abre a fechadura do cofre.
  const passkey = {
    suportado() { return NO_NAVEGADOR && typeof PublicKeyCredential !== 'undefined' && !!(navigator.credentials && navigator.credentials.create); },
    async criar(login, nome) {
      const prf = aleatorio(32);
      const cred = await navigator.credentials.create({ publicKey: {
        rp: { name: 'TIC1', id: location.hostname }, user: { id: aleatorio(16), name: login, displayName: nome || login },
        challenge: aleatorio(32), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }, timeout: 180000,
        extensions: { prf: { eval: { first: prf } } } } });
      const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
      if (!ext.prf || ext.prf.enabled === false) throw erro('passkey-prf', 'Este celular, computador ou navegador não oferece o tipo de passkey que o TIC1 precisa (PRF). Continue usando o Kit de acesso.');
      const id = b64u(new Uint8Array(cred.rawId));
      let segredo = ext.prf.results && ext.prf.results.first ? new Uint8Array(ext.prf.results.first) : null;
      if (!segredo) segredo = (await passkey.obter([{ id, prf: b64u(prf) }])).segredo;
      return { id, prf: b64u(prf), segredo };
    },
    async obter(lista) {
      if (!lista.length) throw erro('passkey-nenhuma', 'Esta conta ainda não tem passkey. Entre com o Kit de acesso e ative uma passkey no menu do usuário.');
      const porId = {};
      for (const p of lista) porId[p.id] = { first: deb64u(p.prf) };
      const a = await navigator.credentials.get({ publicKey: {
        challenge: aleatorio(32), rpId: location.hostname, userVerification: 'required', timeout: 180000,
        allowCredentials: lista.map(p => ({ type: 'public-key', id: deb64u(p.id) })),
        extensions: { prf: { evalByCredential: porId } } } });
      const ext = a.getClientExtensionResults ? a.getClientExtensionResults() : {};
      const r = ext.prf && ext.prf.results && ext.prf.results.first;
      if (!r) throw erro('passkey-prf', 'A passkey respondeu, mas sem o segredo de que o TIC1 precisa (PRF). Use o Kit de acesso.');
      return { id: b64u(new Uint8Array(a.rawId)), segredo: new Uint8Array(r) };
    }
  };
  function kitParaQr(login, kit) { return 'TIC1KIT1:' + login + ':' + kit; }
  function lerQrKit(txt) {
    const m = /^TIC1KIT1:([a-z0-9][a-z0-9._-]{1,31}):(A1-[0-9A-Z-]+)$/.exec(String(txt || '').trim());
    if (!m) throw erro('kit-invalido', 'Este QR code não é um Kit de acesso do TIC1.');
    return { login: m[1], kit: normalizarKit(m[2]) };
  }

  // ---------------------------------------------------------------- cifragem, envelopes, assinaturas

  function aesImportar(cru, extr) { return sutil.importKey('raw', cru, 'AES-GCM', !!extr, ['encrypt', 'decrypt']); }
  async function aesCifrar(chave, dados, aad) {
    const iv = aleatorio(12);
    const ct = new Uint8Array(await sutil.encrypt({ name: 'AES-GCM', iv, additionalData: codif.encode(aad) }, chave, bytes(dados)));
    return { iv, ct };
  }
  async function aesDecifrar(chave, iv, ct, aad) {
    return new Uint8Array(await sutil.decrypt({ name: 'AES-GCM', iv, additionalData: codif.encode(aad) }, chave, ct));
  }
  async function chaveEnvelope(seg, ephRaw, contexto) {
    const hk = await sutil.importKey('raw', seg, 'HKDF', false, ['deriveBits']);
    const bits = await sutil.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: ephRaw, info: codif.encode('tic1-env|' + contexto) }, hk, 256);
    return aesImportar(new Uint8Array(bits));
  }
  async function embrulhar(dados, pubCif, contexto) {
    const pub = typeof pubCif === 'string' ? await importarPubCif(pubCif) : pubCif;
    const eph = await sutil.generateKey(ECDH, true, ['deriveBits']);
    const ephRaw = new Uint8Array(await sutil.exportKey('raw', eph.publicKey));
    const seg = new Uint8Array(await sutil.deriveBits({ name: 'ECDH', public: pub }, eph.privateKey, 256));
    const k = await chaveEnvelope(seg, ephRaw, contexto);
    const r = await aesCifrar(k, dados, 'tic1-env|' + contexto);
    return { e: b64u(ephRaw), iv: b64u(r.iv), c: b64u(r.ct) };
  }
  async function desembrulhar(w, privCif, contexto) {
    const ephRaw = deb64u(w.e);
    const eph = await sutil.importKey('raw', ephRaw, ECDH, false, []);
    const seg = new Uint8Array(await sutil.deriveBits({ name: 'ECDH', public: eph }, privCif, 256));
    const k = await chaveEnvelope(seg, ephRaw, contexto);
    return aesDecifrar(k, deb64u(w.iv), deb64u(w.c), 'tic1-env|' + contexto);
  }
  async function assinar(priv, obj) {
    return b64u(new Uint8Array(await sutil.sign({ name: 'ECDSA', hash: 'SHA-256' }, priv, codif.encode(canon(obj)))));
  }
  async function verificar(pub, obj, sig) {
    try { return await sutil.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, deb64u(sig), codif.encode(canon(obj))); }
    catch (e) { return false; }
  }
  async function hmac(chave, msg) {
    const k = await sutil.importKey('raw', codif.encode(chave), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return b64u(new Uint8Array(await sutil.sign('HMAC', k, codif.encode(msg))));
  }
  async function fluxo(u8, Tipo) {
    const s = new Blob([u8]).stream().pipeThrough(new Tipo('deflate-raw'));
    return new Uint8Array(await new Response(s).arrayBuffer());
  }
  function comprimir(u8) { return fluxo(u8, CompressionStream); }
  function descomprimir(u8) { return fluxo(u8, DecompressionStream); }

  // ---------------------------------------------------------------- datas (sempre no fuso de Brasília)

  const fmtPartes = new Intl.DateTimeFormat('en-GB', { timeZone: FUSO, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  function partes(t) {
    const o = {};
    for (const p of fmtPartes.formatToParts(t instanceof Date ? t : new Date(t))) o[p.type] = p.value;
    return { a: o.year, m: o.month, d: o.day, h: o.hour === '24' ? '00' : o.hour, mi: o.minute };
  }
  function fmtDataHora(t) { const p = partes(t); return p.d + '/' + p.m + '/' + p.a + ' ' + p.h + ':' + p.mi; }
  function fmtTL(t) { const p = partes(t); return p.d + '/' + p.m + ', ' + p.h + ':' + p.mi; }
  function fmtDM(t) { const p = partes(t); return p.d + '/' + p.m; }
  function fmtHora(t) { const p = partes(t); return p.h + ':' + p.mi; }
  function isoDia(t) { const p = partes(t); return p.a + '-' + p.m + '-' + p.d; }
  function somaDiasIso(iso, n) {
    const [a, m, d] = iso.split('-').map(Number);
    return new Date(Date.UTC(a, m - 1, d + n)).toISOString().slice(0, 10);
  }
  function isoParaBR(iso) { const [a, m, d] = iso.split('-'); return d + '/' + m + '/' + a; }
  function isoValido(iso) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(iso))) return false;
    const [a, m, d] = iso.split('-').map(Number);
    const x = new Date(Date.UTC(a, m - 1, d));
    return x.getUTCFullYear() === a && x.getUTCMonth() === m - 1 && x.getUTCDate() === d;
  }
  function rotuloCriada(t, agora) {
    const hj = isoDia(agora), dt = isoDia(t);
    if (dt === hj) return 'Hoje, ' + fmtHora(t);
    if (dt === somaDiasIso(hj, -1)) return 'Ontem, ' + fmtHora(t);
    return isoParaBR(dt);
  }
  function rotuloRelativo(t, agora) {
    const d = (agora - t) / 1000;
    if (d < 60) return 'agora';
    if (d < 3600) return 'há ' + Math.floor(d / 60) + ' min';
    if (d < 86400) return 'há ' + Math.floor(d / 3600) + ' h';
    const n = Math.floor(d / 86400);
    return n === 1 ? 'há 1 dia' : 'há ' + n + ' dias';
  }
  function rotuloAgenda(iso, agora) {
    if (!isoValido(iso)) return [iso, false];
    const hj = isoDia(agora);
    const futuro = iso >= hj;
    if (iso === hj) return ['Hoje, ' + isoParaBR(iso), futuro];
    if (iso === somaDiasIso(hj, 1)) return ['Amanhã, ' + isoParaBR(iso), futuro];
    return [isoParaBR(iso), futuro];
  }
  function duracaoLegivel(ms) {
    const s = Math.max(0, Math.round(ms / 1000));
    return s >= 60 ? Math.floor(s / 60) + ' min ' + (s % 60) + ' s' : s + ' s';
  }

  // ---------------------------------------------------------------- referências e textos

  const CONDS = [
    { key: 'has', nome: 'Hipertensão arterial', ex: 'I10' },
    { key: 'ic', nome: 'Insuficiência cardíaca', ex: 'I50.0' },
    { key: 'arr', nome: 'Arritmias', ex: 'I48.0' },
    { key: 'isq', nome: 'Cardiopatia isquêmica', ex: 'I25.1' },
    { key: 'valv', nome: 'Valvopatias', ex: 'I35.0' }
  ];
  const PRIORIDADES = { 'Urgente': 1, 'Prioritária': 1, 'Eletiva': 1 };
  const EXTS = { pdf: 'PDF', png: 'IMG', jpg: 'IMG', jpeg: 'IMG', webp: 'IMG', heic: 'IMG', dcm: 'DCM', txt: 'TXT', csv: 'TXT', docx: 'DOC', xlsx: 'DOC' };
  const MIME_NA_TELA = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp' };
  const RE_HORA = /^([01]\d|2[0-3]):[0-5]\d$/;

  function limpo(s, max) {
    s = String(s == null ? '' : s);
    if (typeof s.toWellFormed === 'function') s = s.toWellFormed();
    s = s.trim();
    const cps = Array.from(s);
    return cps.length > max ? cps.slice(0, max).join('') : s;
  }
  function ouTraco(s) { return s === '' ? '—' : s; }
  function extensao(nome) { const m = /\.([A-Za-z0-9]+)$/.exec(nome || ''); return m ? m[1].toLowerCase() : ''; }
  function tamanhoLegivel(n) {
    if (n >= 1048576) return (n / 1048576).toFixed(1).replace('.', ',') + ' MB';
    return Math.ceil(n / 1024) + ' KB';
  }
  function resumo(t, n) { const c = Array.from(t); return c.length > n ? c.slice(0, n).join('') + '…' : t; }

  function completarExibicao(u) {
    const partesNome = String(u.nome || '').trim().split(/\s+/).filter(Boolean);
    let titulo = '', resto = partesNome;
    if (partesNome.length) {
      const p = partesNome[0].toLowerCase().replace(/\.$/, '');
      if (p === 'dr' || p === 'dra') { titulo = partesNome[0].endsWith('.') ? partesNome[0] : partesNome[0] + '.'; resto = partesNome.slice(1); }
    }
    if (!u.curto) u.curto = resto.length ? (titulo + ' ' + resto[0]).trim() : u.nome;
    if (!u.ini) {
      let ini = '';
      for (const w of resto) {
        if (['da', 'de', 'do', 'das', 'dos', 'e'].includes(w.toLowerCase())) continue;
        ini += Array.from(w)[0].toUpperCase();
        if (ini.length === 2) break;
      }
      u.ini = ini;
    }
    if (!u.tag) {
      if (u.perfil === 'especialista') u.tag = 'Especialista · Cardiologia';
      else if (titulo.toLowerCase().startsWith('dra')) u.tag = 'Médica solicitante';
      else if (titulo) u.tag = 'Médico solicitante';
      else u.tag = 'Solicitante';
    }
    if (!u.unidade) u.unidade = u.perfil === 'especialista' ? 'Centro de cardiologia' : 'Unidade solicitante';
    return u;
  }
  function senhaFraca(senha, login) {
    senha = String(senha || '');
    if (Array.from(senha).length < 10) return 'A senha precisa ter pelo menos 10 caracteres.';
    if (login && senha.toLowerCase().includes(String(login).toLowerCase())) return 'A senha não pode conter o login.';
    let c = 0;
    if (/\p{Ll}/u.test(senha)) c++;
    if (/\p{Lu}/u.test(senha)) c++;
    if (/\p{Nd}/u.test(senha)) c++;
    if (/[^\p{L}\p{Nd}]/u.test(senha)) c++;
    if (c < 2) return 'Misture pelo menos dois tipos de caractere (letras, números ou símbolos).';
    return '';
  }

  // ---------------------------------------------------------------- regras do caso (portadas de casos.go)

  function novoEstado() { return { casos: new Map(), agenda: [], notifs: [], salas: new Map() }; }
  function idDoCaso(t, n) { return 'TIC-' + partes(t).a + '-' + String(n).padStart(4, '0'); }
  function vinculado(c, login) { return c.solicitanteLogin === login || (!!c.especialistaLogin && c.especialistaLogin === login); }
  function podeVer(c, u) {
    if (vinculado(c, u.login)) return true;
    if (u.perfil === 'especialista') return (c.status === 'aguardando' && !c.especialistaLogin) || c.recusadoPor === u.login;
    return false;
  }
  function outroLado(c, login) { return login === c.solicitanteLogin ? c.especialistaLogin : c.solicitanteLogin; }
  function tl(c, t, texto) { c.timeline.push({ t: fmtTL(t), e: texto }); }
  function notificar(E, ctx, para, titulo, corpo, caso, tipo, sufixo) {
    const alvos = (para || []).filter(Boolean);
    if (!alvos.length) return;
    if (tipo === 'mensagem') {
      for (let i = E.notifs.length - 1; i >= 0 && i >= E.notifs.length - 20; i--) {
        const n = E.notifs[i];
        if (n.tipo === tipo && n.caso === caso && n.para.length === 1 && alvos.length === 1 && n.para[0] === alvos[0]) {
          n.corpo = corpo; n.em = ctx.t;
          E.notifs.splice(i, 1); E.notifs.push(n);
          return;
        }
      }
    }
    E.notifs.push({ id: 'n' + ctx.cid + (sufixo ? '-' + sufixo : ''), para: alvos, titulo, corpo, caso, tipo, em: ctx.t });
    if (E.notifs.length > 2000) E.notifs.splice(0, E.notifs.length - 2000);
  }
  function tirarAgendaFutura(E, c, t) {
    const hj = isoDia(t);
    E.agenda = E.agenda.filter(a => !(a.caseId === c.id && a.dataISO >= hj));
  }
  function validarArquivos(arqs) {
    if (!Array.isArray(arqs)) return 'Lista de arquivos inválida.';
    if (arqs.length > 20) return 'No máximo 20 arquivos por vez.';
    let total = 0;
    for (const a of arqs) {
      const nome = limpo(String(a && a.nome || '').split(/[\\/]/).pop(), 120);
      if (!EXTS[extensao(nome)]) return 'Tipo de arquivo não permitido: ' + nome + ' (use PDF, imagem, DICOM, TXT/CSV, DOCX ou XLSX).';
      const n = Number(a.bytes);
      if (!Number.isInteger(n) || n <= 0) return 'Arquivo ilegível: ' + nome;
      if (n > MAX_ANEXO) return 'Arquivo maior que 15 MB: ' + nome;
      if (!/^anexos\/[a-z0-9]{16,40}\.bin$/.test(String(a.caminho)) || !a.kf || !a.iv || !/^[0-9a-f]{64}$/.test(String(a.sha))) return 'Anexo malformado: ' + nome;
      total += n;
    }
    if (total > MAX_ANEXOS) return 'Os anexos somam mais de 40 MB.';
    return null;
  }
  function anexosDe(arqs, t, autor) {
    return arqs.map(a => {
      const nome = limpo(String(a.nome).split(/[\\/]/).pop(), 120);
      return { nome, tipo: EXTS[extensao(nome)], tam: tamanhoLegivel(Number(a.bytes)), data: fmtDM(t), autor,
        _arq: { caminho: a.caminho, kf: a.kf, iv: a.iv, sha: a.sha, bytes: Number(a.bytes) } };
    });
  }
  function hashParecer(id, p) {
    return sha256(id + '\n' + p.aval + '\n' + p.hip + '\n' + p.cond + '\n' + p.enc + '\n' + p.autor + '\n' + p.emitidoEm).then(hex);
  }
  function encerrarSala(c, sala, t, texto) {
    tl(c, t, texto);
    sala.presentes = new Map(); sala.rec = new Set(); sala.inicio = null; sala.ultimo = null;
  }

  const SEM_CASO = { criar: 1, exemplo: 1 };
  // Cada regra confere tudo primeiro e só altera o estado se `mutar` for verdadeiro.
  // Retorna a mensagem de erro (as mesmas do servidor antigo) ou null.
  const regras = {
    async criar(E, ev, ctx, mutar) {
      const u = ctx.u, d = ev.dados || {}, n = d.novo;
      if (u.perfil !== 'solicitante') return 'Apenas médicos solicitantes abrem solicitações.';
      if (!n || typeof n !== 'object') return 'Dados da solicitação ausentes.';
      if (mutar && E.casos.has(ctx.n)) return 'Caso já existe.';
      if (!n.consent) return 'Registre o consentimento do paciente (RN25).';
      const cond = CONDS.find(c => c.key === n.condKey);
      if (!limpo(n.iniciais, 12) || !limpo(n.idade, 3) || !limpo(n.sexo, 1) || !limpo(n.queixa, 1) || !cond || !limpo(n.pergunta, 1)) return 'Preencha os campos obrigatórios (RN08).';
      const arqs = d.arquivos || [];
      const ea = validarArquivos(arqs);
      if (ea) return ea;
      if (!mutar) return null;
      const comorb = [];
      for (const x of (Array.isArray(n.comorb) ? n.comorb : [])) { const y = limpo(x, 40); if (y && comorb.length < 20) comorb.push(y); }
      const prio = PRIORIDADES[n.prio] ? n.prio : 'Prioritária';
      const c = {
        id: idDoCaso(ctx.t, ctx.n), n: ctx.n, condKey: cond.key, iniciais: limpo(n.iniciais, 12).toUpperCase(), idade: limpo(n.idade, 3),
        sexo: limpo(n.sexo, 1).toUpperCase(), municipio: ouTraco(limpo(n.municipio, 80)), cond: cond.nome, cid: cond.ex,
        prio, status: 'aguardando', criada: '', criadoEm: ctx.t.toISOString(), solicitante: u.nome, solicitanteLogin: u.login,
        unidade: limpo(n.unidade, 120) || u.unidade || '', especialista: null, especialistaLogin: '', recusadoPor: '',
        queixa: limpo(n.queixa, 2000), hda: ouTraco(limpo(n.hda, 4000)),
        vitais: { pa: ouTraco(limpo(n.pa, 30)), fc: ouTraco(limpo(n.fc, 30)), fr: ouTraco(limpo(n.fr, 30)), spo2: ouTraco(limpo(n.spo2, 30)), temp: ouTraco(limpo(n.temp, 30)) },
        meds: ouTraco(limpo(n.meds, 2000)), comorb, exf: ouTraco(limpo(n.exf, 2000)), pergunta: limpo(n.pergunta, 2000),
        anexos: anexosDe(arqs, ctx.t, u.curto), msgs: [], timeline: [], agendamento: null, parecer: null, rnds: null, recusa: null, _k2: null
      };
      tl(c, ctx.t, 'Solicitação criada por ' + u.nome);
      tl(c, ctx.t, 'Consentimento do paciente registrado (RN25)');
      tl(c, ctx.t, 'Classificada: ' + cond.nome + ' (' + cond.ex + ') — roteada aos especialistas (RN11)');
      if (c.anexos.length) tl(c, ctx.t, c.anexos.length + ' anexo(s) incluído(s) na solicitação');
      E.casos.set(ctx.n, c);
      notificar(E, ctx, ctx.destinatarios.filter(l => l !== u.login && l !== COORD), 'Novo caso na fila',
        c.id + ' — ' + cond.nome + ' (' + cond.ex + '), prioridade ' + prio.toLowerCase() + ', aguarda aceite.', c.id, 'fila');
      return null;
    },

    async exemplo(E, ev, ctx, mutar) {
      if (ctx.u.login !== COORD) return 'Somente a coordenação carrega casos de exemplo.';
      const s = ev.dados && ev.dados.caso;
      if (!s || !s.solicitanteLogin) return 'Exemplo inválido.';
      if (E.casos.has(ctx.n)) return 'Caso já existe.';
      if (!mutar) return null;
      const c = Object.assign({ especialista: null, especialistaLogin: '', recusadoPor: '', anexos: [], msgs: [], timeline: [], comorb: [], agendamento: null, parecer: null, rnds: null, recusa: null }, copia(s));
      c.id = idDoCaso(ctx.t, ctx.n); c.n = ctx.n; c._k2 = ev.dados.k2 || null;
      c.anexos = (c.anexos || []).map(a => ({ nome: a.nome, tipo: a.tipo, tam: a.tam, data: a.data }));
      E.casos.set(ctx.n, c);
      for (const a of (ev.dados.agenda || [])) E.agenda.push({ id: 'ag' + ctx.cid + '-' + E.agenda.length, caseId: c.id, dataISO: a.dataISO, hora: a.hora });
      (ev.dados.notifs || []).forEach((x, i) => notificar(E, ctx, x.para, x.titulo, String(x.corpo).split('{{ID}}').join(c.id), c.id, x.tipo, i + 1));
      return null;
    },

    async aceitar(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u;
      if (u.perfil !== 'especialista') return 'Apenas especialistas aceitam casos (RN17).';
      if (c.status !== 'aguardando' || c.especialistaLogin) return 'Este caso já foi aceito ou não está mais aguardando aceite.';
      const k2 = ev.dados && ev.dados.k2;
      if (!/^K2:[a-z0-9]{8,32}$/.test(String(k2 || ''))) return 'Chave do caso ausente.';
      if (!mutar) return null;
      c.status = 'em_analise'; c.especialista = u.nome; c.especialistaLogin = u.login; c._k2 = k2;
      tl(c, ctx.t, 'Caso aceito pelo especialista ' + u.nome + ' (RN17)');
      notificar(E, ctx, [c.solicitanteLogin], 'Caso aceito', c.id + ' foi aceito por ' + u.nome + ' e está em análise.', c.id, 'status');
      return null;
    },

    async recusar(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, d = ev.dados || {};
      if (u.perfil !== 'especialista' || c.status !== 'aguardando' || c.especialistaLogin) return 'Este caso não pode mais ser recusado.';
      let motivo = limpo(d.motivo, 200);
      if (!motivo) return 'Informe o motivo da recusa.';
      if (!mutar) return null;
      const t = limpo(d.texto, 1000);
      if (t) motivo += ' — ' + t;
      c.status = 'recusada'; c.recusadoPor = u.login;
      c.recusa = { motivo, em: fmtDataHora(ctx.t) };
      tl(c, ctx.t, 'Caso recusado pelo especialista ' + u.nome + ' (RN17)');
      notificar(E, ctx, [c.solicitanteLogin], 'Caso recusado', c.id + ' — ' + limpo(d.motivo, 200) + '.', c.id, 'status');
      return null;
    },

    async agendar(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, d = ev.dados || {};
      if (!vinculado(c, u.login)) return 'Somente os profissionais vinculados ao caso podem fazer isso (RN19).';
      if (c.status !== 'em_analise') return 'Só é possível agendar casos em análise.';
      if (!isoValido(d.data) || d.data < isoDia(ctx.t) || !RE_HORA.test(String(d.hora || ''))) return 'Informe uma data (a partir de hoje) e um horário válidos.';
      if (!mutar) return null;
      const br = isoParaBR(d.data);
      c.status = 'agendada';
      c.agendamento = { data: br, hora: d.hora, dataISO: d.data, obs: limpo(d.obs, 500) };
      E.agenda.push({ id: 'ag' + ctx.cid, caseId: c.id, dataISO: d.data, hora: d.hora });
      tl(c, ctx.t, 'Videochamada agendada para ' + br + ' às ' + d.hora + ' por ' + u.curto + ' (RF01)');
      notificar(E, ctx, [outroLado(c, u.login)], 'Videochamada agendada', c.id + ' — reunião em ' + br + ' às ' + d.hora + ' com ' + u.nome + '.', c.id, 'agenda');
      return null;
    },

    async cancelarReuniao(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u;
      if (!vinculado(c, u.login)) return 'Somente os profissionais vinculados ao caso podem fazer isso (RN19).';
      if (c.status !== 'agendada') return 'Não há reunião agendada para este caso.';
      if (!mutar) return null;
      tirarAgendaFutura(E, c, ctx.t);
      c.status = 'em_analise'; c.agendamento = null;
      tl(c, ctx.t, 'Reunião agendada cancelada por ' + u.curto + ' (CDU021)');
      notificar(E, ctx, [outroLado(c, u.login)], 'Reunião cancelada', c.id + ' — ' + u.nome + ' cancelou a videochamada agendada.', c.id, 'agenda');
      return null;
    },

    async mensagem(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u;
      if (!vinculado(c, u.login)) return 'Somente os profissionais vinculados ao caso podem fazer isso (RN19).';
      if (!['em_analise', 'agendada', 'respondida'].includes(c.status)) return 'A discussão está disponível após o aceite do caso.';
      const texto = limpo(ev.dados && ev.dados.texto, 2000);
      if (!texto) return 'Mensagem vazia.';
      if (!mutar) return null;
      c.msgs.push({ de: u.login === c.especialistaLogin ? 'e' : 's', autor: u.curto, hora: fmtHora(ctx.t), texto, uid: u.login, id: ev.id });
      notificar(E, ctx, [outroLado(c, u.login)], 'Nova mensagem', c.id + ' — ' + u.curto + ': ' + resumo(texto, 90), c.id, 'mensagem');
      return null;
    },

    async anexar(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, arqs = ev.dados && ev.dados.arquivos;
      if (!vinculado(c, u.login)) return 'Somente os profissionais vinculados ao caso podem fazer isso (RN19).';
      if (c.status === 'recusada' || c.status === 'registrada') return 'Este caso não aceita novos anexos.';
      if (!Array.isArray(arqs) || !arqs.length) return 'Nenhum arquivo enviado.';
      const ea = validarArquivos(arqs);
      if (ea) return ea;
      if (!mutar) return null;
      const novos = anexosDe(arqs, ctx.t, u.curto);
      c.anexos.push.apply(c.anexos, novos);
      tl(c, ctx.t, novos.length + ' anexo(s) adicionado(s) por ' + u.curto);
      notificar(E, ctx, [outroLado(c, u.login)], 'Novo anexo', c.id + ' — ' + u.curto + ' anexou ' + novos.length + ' arquivo(s).', c.id, 'anexo');
      return null;
    },

    async parecer(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, p = ev.dados && ev.dados.parecer;
      if (u.perfil !== 'especialista' || c.especialistaLogin !== u.login) return 'Somente o especialista responsável emite o parecer (RN20).';
      if (c.status !== 'em_analise' && c.status !== 'agendada') return 'O parecer já foi emitido ou o caso não está em análise.';
      if (!p || !limpo(p.aval, 1) || !limpo(p.hip, 1) || !limpo(p.cond, 1)) return 'Preencha avaliação, hipótese diagnóstica e conduta (RN08).';
      if (!mutar) return null;
      const autor = u.nome + (u.crm ? ' · ' + u.crm : '');
      const par = { aval: limpo(p.aval, 6000), hip: limpo(p.hip, 1000), cond: limpo(p.cond, 6000), enc: limpo(p.enc, 200), emitidoEm: fmtDataHora(ctx.t), autor };
      par.hash = await hashParecer(c.id, par);
      par.assinatura = { alg: 'ECDSA P-256 / SHA-256', chave: ctx.impressaoAutor, valor: ctx.sig };
      c.parecer = par; c.status = 'respondida';
      tirarAgendaFutura(E, c, ctx.t);
      tl(c, ctx.t, 'Parecer especializado emitido por ' + u.nome + ' (RN20/RN21) — SHA-256 ' + par.hash.slice(0, 12) + '… · assinado digitalmente pelo especialista');
      notificar(E, ctx, [c.solicitanteLogin], 'Parecer emitido', c.id + ' — parecer de ' + u.nome + ' disponível.', c.id, 'status');
      return null;
    },

    async rnds(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u;
      if (u.perfil !== 'especialista' || c.especialistaLogin !== u.login) return 'Somente o especialista responsável registra no RNDS.';
      if (c.status !== 'respondida' || !c.parecer) return 'O registro no RNDS exige parecer emitido (RN23).';
      if (!mutar) return null;
      const h = c.parecer.hash || hex(await sha256(c.id + c.parecer.aval + c.parecer.cond));
      const p = partes(ctx.t);
      c.rnds = { protocolo: 'RNDS-SIM-' + p.a + p.m + p.d + '-' + String(ev.id).slice(0, 6).toUpperCase(), data: fmtDataHora(ctx.t), hash: h.slice(0, 8) + '…' + h.slice(-4) };
      c.status = 'registrada';
      tl(c, ctx.t, 'Interconsulta registrada no RNDS/e‑SUS (RN23) — envio simulado neste MVP, protocolo ' + c.rnds.protocolo);
      notificar(E, ctx, [c.solicitanteLogin], 'Registro RNDS (simulado)', c.id + ' — protocolo ' + c.rnds.protocolo + '.', c.id, 'status');
      return null;
    },

    async 'chamada-entrou'(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, sessao = ev.dados && ev.dados.sessao;
      if (!vinculado(c, u.login) || c.status === 'recusada') return 'Sala restrita aos profissionais vinculados ao caso (RN19).';
      if (!/^[a-z0-9]{8,32}$/.test(String(sessao || ''))) return 'Sessão inválida.';
      if (!mutar) return null;
      let sala = E.salas.get(c.n);
      if (!sala) { sala = { presentes: new Map(), rec: new Set(), inicio: null, ultimo: null }; E.salas.set(c.n, sala); }
      if (sala.presentes.size && sala.ultimo && ctx.t - sala.ultimo > 3 * 3600 * 1000) encerrarSala(c, sala, sala.ultimo, 'Videochamada encerrada (sem registro de saída)');
      if (!sala.presentes.size) { sala.inicio = ctx.t; tl(c, ctx.t, 'Videochamada iniciada por ' + u.curto + ' (RF12) — sala restrita aos vinculados ao caso (RN19)'); }
      else if (!sala.presentes.has(u.login)) tl(c, ctx.t, u.curto + ' entrou na videochamada');
      sala.presentes.set(u.login, sessao); sala.ultimo = ctx.t;
      return null;
    },

    async 'chamada-saiu'(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, sessao = ev.dados && ev.dados.sessao;
      const sala = E.salas.get(c.n);
      if (!sala || sala.presentes.get(u.login) !== sessao) return 'Não está na sala.';
      if (!mutar) return null;
      sala.presentes.delete(u.login); sala.rec.delete(u.login); sala.ultimo = ctx.t;
      if (!sala.presentes.size) encerrarSala(c, sala, ctx.t, 'Videochamada encerrada (duração: ' + duracaoLegivel(ctx.t - sala.inicio) + ')');
      return null;
    },

    async 'chamada-rec'(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u;
      const sala = E.salas.get(c.n);
      if (!sala || !sala.presentes.has(u.login)) return 'Não está na sala.';
      if (!mutar) return null;
      const on = !!(ev.dados && ev.dados.on);
      if (on && !sala.rec.size) tl(c, ctx.t, 'Gravação iniciada por ' + u.curto + ', com aviso visível a todos os participantes (RF13)');
      if (on) sala.rec.add(u.login); else sala.rec.delete(u.login);
      sala.ultimo = ctx.t;
      return null;
    },

    async gravacao(E, ev, ctx, mutar) {
      const c = ctx.c, u = ctx.u, d = ev.dados || {};
      if (!vinculado(c, u.login)) return 'Somente os profissionais vinculados ao caso podem fazer isso (RN19).';
      if (!/^[0-9a-f]{64}$/.test(String(d.sha256 || ''))) return 'Gravação sem SHA-256.';
      if (!mutar) return null;
      const cifrada = /^[a-z0-9]{16}$/.test(String(d.rid || '')) && !!d.kr;
      if (cifrada) (c._gravacoes = c._gravacoes || []).push({ rid: d.rid, kr: d.kr, mime: limpo(d.mime, 60), sha: d.sha256, duracaoMs: Number(d.duracaoMs) || 0, bytes: Number(d.bytes) || 0, autor: u.curto, data: fmtDataHora(ctx.t) });
      tl(c, ctx.t, 'Gravação encerrada — arquivo ' + (cifrada ? 'cifrado ' : '') + 'de ' + duracaoLegivel(Number(d.duracaoMs) || 0) + ' (' + tamanhoLegivel(Number(d.bytes) || 0) +
        ') salvo no computador de ' + u.curto + ' · SHA-256 ' + d.sha256.slice(0, 12) + '… (RF13)');
      return null;
    },

    async sinal(E, ev, ctx) {
      if (!vinculado(ctx.c, ctx.u.login)) return 'Sala restrita aos profissionais vinculados ao caso (RN19).';
      return null;
    }
  };

  // Conferência comum a todas as ações sobre um caso existente.
  async function conferir(E, ev, ctx, mutar) {
    const regra = regras[ev.tipo];
    if (!regra) return 'Ação desconhecida.';
    if (!SEM_CASO[ev.tipo]) {
      const c = E.casos.get(ctx.n);
      if (!c || (ctx.u.login !== COORD && !podeVer(c, ctx.u))) return 'Caso não encontrado ou sem acesso (RN19).';
      if (c._k2 && ctx.rotulo !== c._k2) {
        const k1Permitido = ctx.rotulo === 'K1' && ev.tipo === 'anexar' && ctx.u.login === c.solicitanteLogin;
        if (!k1Permitido) return 'Evento cifrado com chave que não é a do caso.';
      }
      ctx.c = c;
    }
    return regra(E, ev, ctx, mutar);
  }

  function estadoPara(E, u, agora, lida) {
    const cases = [], vis = new Set();
    for (const c of E.casos.values()) {
      if (!podeVer(c, u)) continue;
      const cp = {};
      for (const k of Object.keys(c)) if (k[0] !== '_') cp[k] = c[k];
      if (c.criadoEm) cp.criada = rotuloCriada(new Date(c.criadoEm), agora);
      cp.anexos = c.anexos.map((a, i) => {
        const o = { nome: a.nome, tipo: a.tipo, tam: a.tam, data: a.data };
        if (a.autor) o.autor = a.autor;
        if (a._arq) o.url = 'tic1:' + c.n + ':' + i;
        return o;
      });
      cp.gravacoes = (c._gravacoes || []).map(g => ({ rid: g.rid, data: g.data, duracao: duracaoLegivel(g.duracaoMs), tam: tamanhoLegivel(g.bytes), autor: g.autor }));
      cases.push(copia(cp));
      vis.add(c.id);
    }
    cases.sort((a, b) => (a.id < b.id ? 1 : a.id > b.id ? -1 : 0));
    const agenda = [];
    for (const a of E.agenda) {
      if (!vis.has(a.caseId)) continue;
      const r = rotuloAgenda(a.dataISO, agora);
      agenda.push({ id: a.id, caseId: a.caseId, dataISO: a.dataISO, hora: a.hora, quando: r[0], futuro: r[1] });
    }
    agenda.sort((x, y) => {
      if (x.futuro !== y.futuro) return x.futuro ? -1 : 1;
      const kx = x.dataISO + x.hora, ky = y.dataISO + y.hora;
      return x.futuro ? (kx < ky ? -1 : kx > ky ? 1 : 0) : (kx > ky ? -1 : kx < ky ? 1 : 0);
    });
    const notifs = [];
    for (let i = E.notifs.length - 1; i >= 0 && notifs.length < 50; i--) {
      const n = E.notifs[i];
      if (!n.para.includes(u.login)) continue;
      notifs.push({ id: n.id, titulo: n.titulo, corpo: n.corpo, caso: n.caso, quando: rotuloRelativo(n.em, agora), lida: !!(lida && lida(n)) });
    }
    return { cases, agenda, notifs };
  }

  // ---------------------------------------------------------------- GitHub

  function cabecalhosBase(token) {
    const h = { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' };
    if (token) h.Authorization = 'Bearer ' + token;
    return h;
  }
  function esperar(ms) { return new Promise(r => setTimeout(r, ms)); }

  class GitHubDados {
    constructor(o) {
      this.api = (o.api || 'https://api.github.com').replace(/\/$/, '');
      this.dono = o.dono; this.repo = o.repo;
      this.token = o.token; this.f = o.fetch; this.aoAviso = o.aoAviso || function () {};
      this._fila = Promise.resolve(); this._etag = null;
    }
    caminho(p) { return this.api + '/repos/' + this.dono + '/' + this.repo + p; }
    async req(metodo, url, o) {
      o = o || {};
      for (let tentativa = 0; ; tentativa++) {
        const h = Object.assign(cabecalhosBase(await this.token()), o.cabecalhos || {});
        const init = { method: metodo, headers: h };
        if (NO_NAVEGADOR) init.cache = 'no-store';
        if (o.keepalive) init.keepalive = true;
        if (o.corpo !== undefined) { h['Content-Type'] = 'application/json'; init.body = JSON.stringify(o.corpo); }
        const r = await this.f(url, init);
        if (r.status === 304 || r.ok) return r;
        const restante = r.headers.get('x-ratelimit-remaining');
        const limite = r.status === 429 || (r.status === 403 && (restante === '0' || r.headers.get('retry-after')));
        if (limite && tentativa < 3) {
          const ra = Number(r.headers.get('retry-after'));
          const reset = Number(r.headers.get('x-ratelimit-reset'));
          const ms = ra ? ra * 1000 : reset ? Math.max(1000, reset * 1000 - Date.now()) : 5000 * (tentativa + 1);
          this.aoAviso('O GitHub limitou o acesso por alguns segundos; tentando de novo.');
          await esperar(Math.min(ms, 60000));
          continue;
        }
        if ((r.status === 409 || r.status >= 500) && tentativa < 3 && !o.semRepetir) { await esperar(800 * (tentativa + 1)); continue; }
        let msg = '';
        try { msg = (await r.json()).message || ''; } catch (e) { /* sem corpo */ }
        throw erro('github-' + r.status, 'GitHub respondeu ' + r.status + (msg ? ' (' + msg + ')' : '') + '.');
      }
    }
    serial(fn) { const p = this._fila.then(fn, fn); this._fila = p.catch(() => {}); return p; }
    async listarTodos() {
      const todos = [];
      for (let pag = 1; pag < 1000; pag++) {
        const r = await this.req('GET', this.caminho('/issues/comments?sort=created&direction=asc&per_page=100&page=' + pag));
        const lista = await r.json();
        todos.push.apply(todos, lista);
        if (lista.length < 100) break;
      }
      return todos;
    }
    // Endereço fixo + ETag: sem novidades o GitHub responde 304, que não consome o limite.
    async sondar(conhecido) {
      const base = '/issues/comments?sort=updated&direction=desc&per_page=100';
      const h = this._etag ? { 'If-None-Match': this._etag } : {};
      const r = await this.req('GET', this.caminho(base), { cabecalhos: h });
      if (r.status === 304) return null;
      this._etag = r.headers.get('etag');
      let lista = await r.json();
      const todos = lista.slice();
      for (let pag = 2; lista.length === 100 && !lista.some(c => conhecido(c)); pag++) {
        lista = await (await this.req('GET', this.caminho(base + '&page=' + pag))).json();
        todos.push.apply(todos, lista);
      }
      return todos;
    }
    criarIssue(titulo) {
      return this.serial(async () => (await this.req('POST', this.caminho('/issues'), { corpo: { title: titulo }, semRepetir: true })).json());
    }
    comentar(n, corpo, o) {
      if (o && o.keepalive) return this.req('POST', this.caminho('/issues/' + n + '/comments'), { corpo: { body: corpo }, keepalive: true, semRepetir: true }).then(r => r.json());
      return this.serial(async () => (await this.req('POST', this.caminho('/issues/' + n + '/comments'), { corpo: { body: corpo }, semRepetir: true })).json());
    }
    gravarArquivo(caminho, conteudo) {
      return this.serial(async () => (await this.req('PUT', this.caminho('/contents/' + caminho), { corpo: { message: 'anexo cifrado', content: b64(conteudo) } })).json());
    }
    async lerArquivo(caminho) {
      const r = await this.req('GET', this.caminho('/contents/' + caminho), { cabecalhos: { Accept: 'application/vnd.github.raw+json' } });
      return new Uint8Array(await r.arrayBuffer());
    }
  }

  function pemParaDer(pem) { return deb64(String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '')); }
  async function jwtApp(id, chave, agoraS) {
    const now = agoraS || Math.floor(Date.now() / 1000);
    const ench = o => b64u(codif.encode(JSON.stringify(o)));
    const corpo = ench({ alg: 'RS256', typ: 'JWT' }) + '.' + ench({ iat: now - 60, exp: now + 540, iss: String(id) });
    const sig = new Uint8Array(await sutil.sign('RSASSA-PKCS1-v1_5', chave, codif.encode(corpo)));
    return corpo + '.' + b64u(sig);
  }
  function provedorToken(acesso, api, f) {
    if (acesso.pat) return async () => acesso.pat;
    if (!acesso.app) throw erro('acesso', 'Credencial de acesso ao GitHub ausente.');
    let atual = null, chave = null;
    return async () => {
      if (atual && atual.expira - Date.now() > 5 * 60 * 1000) return atual.token;
      if (!chave) chave = await sutil.importKey('pkcs8', pemParaDer(acesso.app.pem), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
      const jwt = await jwtApp(acesso.app.id, chave);
      const r = await f(api.replace(/\/$/, '') + '/app/installations/' + acesso.app.inst + '/access_tokens', { method: 'POST', headers: cabecalhosBase(jwt) });
      if (!r.ok) throw erro('acesso', 'O GitHub recusou a credencial do TIC1 (' + r.status + '). Fale com a coordenação.');
      const d = await r.json();
      atual = { token: d.token, expira: Date.parse(d.expires_at) };
      return atual.token;
    };
  }

  // ---------------------------------------------------------------- armazenamento local

  function armazenamentoMemoria() {
    const m = new Map();
    return { get: async k => m.get(k), set: async (k, v) => { m.set(k, v); }, del: async k => { m.delete(k); } };
  }
  function armazenamentoNavegador(nome) {
    let db = null;
    const abrir = () => db || (db = new Promise((ok, falha) => {
      const r = indexedDB.open(nome || 'tic1', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('kv');
      r.onsuccess = () => ok(r.result);
      r.onerror = () => falha(r.error);
    }));
    const op = (modo, fn) => abrir().then(d => new Promise((ok, falha) => {
      const tx = d.transaction('kv', modo);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => ok(req && req.result);
      tx.onerror = () => falha(tx.error);
    }));
    const mem = armazenamentoMemoria();
    return {
      get: k => op('readonly', s => s.get(k)).catch(() => mem.get(k)),
      set: (k, v) => op('readwrite', s => s.put(v, k)).catch(() => mem.set(k, v)),
      del: k => op('readwrite', s => s.delete(k)).catch(() => mem.del(k))
    };
  }

  // ---------------------------------------------------------------- envelopes de evento

  function aadEvento(n, rotulo) { return 'tic1|' + n + '|' + rotulo; }
  const cacheHash = new Map();
  async function hashFora(fora) {
    const chave = fora.iv + '.' + fora.c;
    let h = cacheHash.get(chave);
    if (!h) { h = b64u((await sha256(chave)).subarray(0, 18)); cacheHash.set(chave, h); }
    return h;
  }
  function ctxChave(n, rotulo, login) { return 'chave|' + n + '|' + rotulo + '|' + login; }

  async function selarEvento(o) {
    // o: {n, rotulo, chave(CryptoKey), ev, priv, embrulhos?}
    const sig = await assinar(o.priv, o.ev);
    let dados = codif.encode(canon({ ev: o.ev, sig }));
    let z = 0;
    if (dados.length > 1024) { dados = await comprimir(dados); z = 1; }
    const r = await aesCifrar(o.chave, dados, aadEvento(o.n, o.rotulo));
    const fora = { t1: ESQUEMA, tp: 'caso', k: o.rotulo, iv: b64u(r.iv), c: b64u(r.ct) };
    if (z) fora.z = 1;
    if (o.embrulhos && o.embrulhos.length) fora.w = o.embrulhos;
    return { corpo: JSON.stringify(fora), sig };
  }
  function dividir(corpo) {
    if (corpo.length <= MAX_CORPO) return [corpo];
    const g = idAleatorio(10), partesC = [];
    const tam = MAX_CORPO - 200;
    for (let i = 0; i < corpo.length; i += tam) partesC.push(corpo.slice(i, i + tam));
    return partesC.map((d, i) => JSON.stringify({ t1: ESQUEMA, g, p: [i, partesC.length], d }));
  }
  async function embrulhosPara(chaveCrua, n, rotulo, destinos) {
    // destinos: [{login, cif}]
    const p = {};
    for (const d of destinos) p[d.login] = await embrulhar(chaveCrua, d.cif, ctxChave(n, rotulo, d.login));
    return { r: rotulo, p };
  }

  // ---------------------------------------------------------------- diretório público (sem nomes nem CRM em claro)
  // No site publicado ficam só: hash do login, chaves públicas, cofre cifrado e o perfil cifrado com a
  // chave do diretório, que cada usuário recebe dentro do seu acesso cifrado.
  async function idLogin(login) { return b64u((await sha256('tic1-login|' + String(login).trim().toLowerCase())).subarray(0, 16)); }
  const CAMPOS_PERFIL = ['login', 'nome', 'curto', 'ini', 'perfil', 'tag', 'crm', 'unidade'];
  async function diretorioPublico(dir) {
    const kdir = aleatorio(32), chave = await aesImportar(kdir);
    const usuarios = [];
    for (const u of dir.usuarios) {
      const id = await idLogin(u.login);
      const perfil = {};
      for (const k of CAMPOS_PERFIL) if (u[k] != null) perfil[k] = u[k];
      const r = await aesCifrar(chave, codif.encode(canon(perfil)), 'tic1-perfil|' + id);
      const e = { id, ass: u.ass, cif: u.cif, cofre: u.cofre, ativo: u.ativo !== false, p: { iv: b64u(r.iv), c: b64u(r.ct) } };
      if (u.desativadoEm) e.desativadoEm = u.desativadoEm;
      if (u.antigas && u.antigas.length) e.antigas = u.antigas;
      usuarios.push(e);
    }
    return { pub: { v: 2, coordenacao: dir.coordenacao, usuarios }, kdir };
  }
  async function abrirDiretorio(pub, kdir) {
    const chave = await aesImportar(kdir);
    const lista = [];
    for (const e of pub.usuarios) {
      try {
        const perfil = JSON.parse(decod.decode(await aesDecifrar(chave, deb64u(e.p.iv), deb64u(e.p.c), 'tic1-perfil|' + e.id)));
        lista.push(Object.assign({}, perfil, { ass: e.ass, cif: e.cif, cofre: e.cofre, ativo: e.ativo, desativadoEm: e.desativadoEm, antigas: e.antigas }));
      } catch (x) { /* perfil ilegível: ignora */ }
    }
    return lista;
  }

  // ---------------------------------------------------------------- gravação cifrada (RF13)
  // O arquivo salvo no computador vai cifrado em blocos de 4 MB; a chave fica no caso (só a dupla vinculada e a
  // coordenação leem). Abrir exige estar logado no TIC1.
  const MAGICO_REC = 'TIC1REC1';
  function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
  async function gravacaoCifrar(dados, meta) {
    const kr = aleatorio(32), chave = await aesImportar(kr), rid = idAleatorio(16);
    const cab = codif.encode(JSON.stringify({ v: 1, rid, caso: meta.caso, mime: meta.mime || 'video/webm' }));
    const partesB = [codif.encode(MAGICO_REC), u32(cab.length), cab];
    const T = 4 * 1024 * 1024;
    for (let i = 0, n = 0; i < dados.length; i += T, n++) {
      const r = await aesCifrar(chave, dados.subarray(i, i + T), 'tic1-rec|' + rid + '|' + n);
      partesB.push(u32(r.ct.length), r.iv, r.ct);
    }
    partesB.push(u32(0));
    return { partes: partesB, rid, kr: b64u(kr) };
  }
  function gravacaoCabecalho(bytes) {
    if (decod.decode(bytes.subarray(0, 8)) !== MAGICO_REC) throw erro('gravacao', 'Este arquivo não é uma gravação do TIC1.');
    const n = new DataView(bytes.buffer, bytes.byteOffset + 8, 4).getUint32(0);
    const cab = JSON.parse(decod.decode(bytes.subarray(12, 12 + n)));
    return Object.assign(cab, { inicio: 12 + n });
  }
  async function gravacaoDecifrar(bytes, kr) {
    const cab = gravacaoCabecalho(bytes), chave = await aesImportar(deb64u(kr)), saida = [];
    let p = cab.inicio, n = 0, fim = false;
    while (p + 4 <= bytes.length) {
      const len = new DataView(bytes.buffer, bytes.byteOffset + p, 4).getUint32(0); p += 4;
      if (len === 0) { fim = true; break; }
      const iv = bytes.subarray(p, p + 12); p += 12;
      saida.push(await aesDecifrar(chave, iv, bytes.subarray(p, p + len), 'tic1-rec|' + cab.rid + '|' + n)); p += len; n++;
    }
    if (!fim) throw erro('gravacao', 'O arquivo da gravação está incompleto ou foi cortado.');
    return { partes: saida, mime: cab.mime, rid: cab.rid, caso: cab.caso };
  }

  // ---------------------------------------------------------------- cliente (o "servidor" no navegador)

  class Cliente {
    constructor(o) {
      this.cfg = o.config;
      this.f = o.fetch || globalThis.fetch.bind(globalThis);
      this.arm = o.armazenamento || armazenamentoMemoria();
      this.agora = o.relogio || (() => new Date());
      this.iter = o.iter || ITER_PADRAO;
      this.esperaAceite = o.esperaAceite != null ? o.esperaAceite : 1500;
      this.dirPub = this.cfg.diretorio || { usuarios: [] };
      this.dir = this.dirPub.v === 2 ? { coordenacao: this.dirPub.coordenacao, usuarios: [] } : this.dirPub;
      this.api = (this.cfg.dados && this.cfg.dados.api) || 'https://api.github.com';
      this.usuario = null;
      this._ouvintes = new Set(); this._ouvSinal = new Set(); this._ouvAviso = new Set();
      this._reiniciarDados();
    }
    _reiniciarDados() {
      this._coment = new Map(); this._dec = new Map(); this._chaves = new Map(); this._pubs = new Map();
      this._E = novoEstado(); this._hashes = new Map(); this._ultimo = new Map(); this._sinais = []; this._sinaisVistos = new Set();
      this._lidas = {}; this._carregado = false; this._regrasNovas = false; this._integridade = [];
      this._gh = null; this._acesso = null;
    }
    usuarioDir(login) { return (this.dir.usuarios || []).find(u => u.login === login) || null; }
    especialistasAtivos() { return (this.dir.usuarios || []).filter(u => u.perfil === 'especialista' && u.ativo !== false); }
    aoMudar(fn) { this._ouvintes.add(fn); return () => this._ouvintes.delete(fn); }
    aoAviso(fn) { this._ouvAviso.add(fn); return () => this._ouvAviso.delete(fn); }
    _avisar(msg) { for (const f of this._ouvAviso) { try { f(msg); } catch (e) { /* ouvinte com erro */ } } }
    _mudou() { for (const f of this._ouvintes) { try { f(); } catch (e) { /* ouvinte com erro */ } } }

    // ----- sessão

    async _entrada(login) {
      if (this.dirPub.v !== 2) return (this.dirPub.usuarios || []).find(u => u.login === login) || null;
      const id = await idLogin(login);
      return (this.dirPub.usuarios || []).find(e => e.id === id) || null;
    }
    async _cofresDe(login, ent) {
      const local = await this.arm.get('cofre:' + login);
      const l = [];
      if (local && (!ent.cofre || String(local.em) > String(ent.cofre.em))) l.push(local);
      if (ent.cofre) l.push(ent.cofre);
      return l;
    }
    // opcoes: {lembrar (padrão true), passkey (usar passkey em vez do Kit)}
    async entrar(login, senha, kitTxt, opcoes) {
      opcoes = opcoes || {};
      login = String(login || '').trim().toLowerCase();
      const ent = await this._entrada(login);
      if (!ent) {
        if (await this.arm.get('pedido:' + login))
          throw erro('pendente', 'Seu cadastro ainda não foi aprovado pela coordenação. Envie o pedido de cadastro abaixo. Depois da aprovação, o acesso libera em poucos minutos.');
        throw erro('credenciais', 'Usuário ou senha inválidos.');
      }
      if (ent.ativo === false) throw erro('desativado', 'Esta conta está desativada. Fale com a coordenação do TIC1.');
      const cofres = await this._cofresDe(login, ent);
      let fator, kitNorm = null;
      if (opcoes.passkey) {
        const lista = [];
        for (const cf of cofres) for (const pk of passkeysDoCofre(cf)) if (!lista.some(x => x.id === pk.id)) lista.push(pk);
        const r = await passkey.obter(lista);
        fator = { tipo: 'passkey', id: r.id, segredo: r.segredo };
      } else {
        kitNorm = kitTxt ? normalizarKit(kitTxt) : await this.arm.get('kit:' + login);
        if (!kitNorm) throw erro('kit', 'Este aparelho ainda não tem a chave secreta da sua conta. Digite ou leia o QR do seu Kit de acesso, ou entre com passkey.');
        fator = { tipo: 'kit', segredo: lerChaveSecreta(kitNorm) };
      }
      let ab = null;
      for (const cf of cofres) { ab = await abrirCofre(cf, login, senha, fator, true); if (ab) break; }
      if (!ab) throw erro('credenciais', opcoes.passkey ? 'Senha incorreta para esta passkey.' : kitTxt ? 'Senha ou chave secreta incorreta.' : 'Usuário ou senha inválidos.');
      if (await pubDaPriv(ab.assPriv) !== ent.ass || await pubDaPriv(ab.cifPriv) !== ent.cif)
        throw erro('chaves', 'As chaves desta conta não conferem com o cadastro publicado. Fale com a coordenação.');
      const assPriv = await importarPrivAss(ab.assPkcs8, false);
      const cifPriv = await importarPrivCif(ab.cifPkcs8, false);
      const u = await this._iniciarSessao(login, ent, assPriv, cifPriv);
      await this.arm.del('pedido:' + login);
      if (opcoes.lembrar === false) {
        await this.arm.del('kit:' + login);
        await this.arm.del('sessao');
      } else {
        if (kitNorm) await this.arm.set('kit:' + login, kitNorm);
        await this.arm.set('sessao', { login, assPriv, cifPriv, expira: Date.now() + SESSAO_MS });
      }
      this._auditar('LOGIN_OK', { fator: fator.tipo, lembrar: opcoes.lembrar !== false });
      return u;
    }
    async restaurar() {
      const s = await this.arm.get('sessao');
      if (!s || !s.expira || s.expira < Date.now()) return null;
      const ent = await this._entrada(s.login);
      if (!ent || ent.ativo === false) { await this.arm.del('sessao'); return null; }
      try { return await this._iniciarSessao(s.login, ent, s.assPriv, s.cifPriv); }
      catch (e) { await this.arm.del('sessao'); return null; }
    }
    async _iniciarSessao(login, ent, assPriv, cifPriv) {
      this._reiniciarDados();
      this._ass = assPriv; this._cif = cifPriv;
      const chaveAcesso = this.dirPub.v === 2 ? ent.id : login;
      const w = this.cfg.acesso && this.cfg.acesso[chaveAcesso];
      if (!w) throw erro('acesso', 'Sua conta ainda não recebeu acesso aos dados. Aguarde a próxima publicação do TIC1 ou fale com a coordenação.');
      this._acesso = JSON.parse(decod.decode(await desembrulhar(w, cifPriv, 'acesso|' + login)));
      if (this.dirPub.v === 2) this.dir = { coordenacao: this.dirPub.coordenacao, usuarios: await abrirDiretorio(this.dirPub, deb64u(this._acesso.dir)) };
      const u = this.usuarioDir(login);
      if (!u) throw erro('acesso', 'Seu perfil não foi encontrado no diretório publicado.');
      this.usuario = u;
      const dados = this.cfg.dados;
      this._gh = new GitHubDados({ api: this.api, dono: dados.dono, repo: dados.repo, token: provedorToken(this._acesso, this.api, this.f), fetch: this.f, aoAviso: m => this._avisar(m) });
      this._lidas = (await this.arm.get('lidas:' + login)) || {};
      return u;
    }
    async sair() {
      this.pararSondagem();
      await this.arm.del('sessao');
      this.usuario = null; this._ass = null; this._cif = null;
      this._reiniciarDados();
    }
    // Apaga deste aparelho a chave secreta, o cofre local e a sessão (computador compartilhado).
    async esquecerAparelho() {
      const login = this.usuario && this.usuario.login;
      await this.arm.del('sessao');
      if (login) for (const k of ['kit:', 'cofre:', 'lidas:']) await this.arm.del(k + login);
      await this.sair();
    }
    async kitDesteAparelho(login) { return (await this.arm.get('kit:' + (login || (this.usuario && this.usuario.login)))) || null; }
    iceServers() {
      const l = (this.cfg.ice || []).slice();
      if (this._acesso && this._acesso.turn) l.push.apply(l, [].concat(this._acesso.turn));
      return l;
    }
    temTurn() { return !!(this._acesso && this._acesso.turn); }
    get regrasNovas() { return this._regrasNovas; }
    get carregado() { return this._carregado; }
    get integridade() { return this._integridade.slice(); }

    // ----- sincronização

    async sincronizar() {
      if (!this._gh) return false;
      let lista;
      if (!this._carregado) { lista = await this._gh.listarTodos(); this._carregado = true; }
      else lista = await this._gh.sondar(c => { const x = this._coment.get(c.id); return !!x && x.atualizado === c.updated_at; });
      let mudou = !lista ? false : this._coment.size === 0 && lista.length === 0 ? true : false;
      for (const c of (lista || [])) {
        const x = this._coment.get(c.id);
        if (x && x.atualizado === c.updated_at) continue;
        const m = /\/issues\/(\d+)$/.exec(c.issue_url || '');
        if (!m) continue;
        this._coment.set(c.id, { id: c.id, n: Number(m[1]), criado: new Date(c.created_at), atualizado: c.updated_at, corpo: c.body || '', editado: !!x });
        mudou = true;
      }
      if (mudou) { await this._recalcular(); this._mudou(); }
      return mudou;
    }
    iniciarSondagem() {
      this.pararSondagem();
      this._sondando = true;
      const passo = async () => {
        if (!this._sondando) return;
        try { await this.sincronizar(); this._falhas = 0; }
        catch (e) { this._falhas = (this._falhas || 0) + 1; if (this._falhas === 3) this._avisar('Sem conexão com o GitHub. Tentando de novo…'); }
        if (!this._sondando) return;
        const oculto = NO_NAVEGADOR && document.visibilityState === 'hidden';
        const ms = this._rapido ? 1000 : oculto ? 15000 : 3000;
        this._timer = setTimeout(passo, ms);
      };
      this._acordar = () => { if (this._sondando) { clearTimeout(this._timer); this._timer = setTimeout(passo, 50); } };
      if (NO_NAVEGADOR) document.addEventListener('visibilitychange', this._acordar);
      passo();
    }
    pararSondagem() {
      this._sondando = false;
      clearTimeout(this._timer);
      if (NO_NAVEGADOR && this._acordar) document.removeEventListener('visibilitychange', this._acordar);
    }
    modoRapido(on) { this._rapido = !!on; if (on && this._acordar) this._acordar(); }

    async _pubAss(login) {
      if (this._pubs.has(login)) return this._pubs.get(login);
      const u = login === COORD ? this.dir.coordenacao : this.usuarioDir(login);
      let k = null;
      if (u && u.ass) {
        const chaves = [{ chave: await importarPubAss(u.ass), ate: null }];
        for (const a of (u.antigas || [])) chaves.push({ chave: await importarPubAss(a.ass), ate: a.ate });
        k = { chaves, impressao: await impressao(u.ass, u.cif) };
      }
      this._pubs.set(login, k);
      return k;
    }
    async _verificarAutor(pub, ev, sig, criado) {
      for (const c of pub.chaves) {
        if (c.ate && criado.toISOString() >= c.ate) continue;
        if (await verificar(c.chave, ev, sig)) return true;
      }
      return false;
    }
    async _restauroValido(fora) {
      const pub = await this._pubAss(COORD);
      return !!(pub && fora.orig && await verificar(pub.chaves[0].chave, fora.orig, fora.sig));
    }
    _eu() { return this._modoCoord ? COORD : this.usuario.login; }

    // Junta comentários divididos, decifra o que for possível, confere assinaturas e aplica as regras.
    async _recalcular() {
      const coments = new Map(this._coment);
      for (const c of this._coment.values()) {
        let fr;
        try { fr = JSON.parse(c.corpo); } catch (e) { continue; }
        if (!fr || fr.t1 !== ESQUEMA || fr.tp !== 'rest' || !fr.orig) continue;
        const chaveR = 'rest|' + c.id + '|' + c.atualizado;
        if (!this._dec.has(chaveR)) this._dec.set(chaveR, await this._restauroValido(fr));
        if (!this._dec.get(chaveR)) continue;
        const o = fr.orig, vivo = coments.get(o.id);
        if (!vivo || vivo.corpo !== o.corpo) coments.set(o.id, { id: o.id, n: o.n, criado: new Date(o.criado), atualizado: 'rest|' + o.atualizado, corpo: o.corpo, editado: false });
      }
      const ids = Array.from(coments.keys()).sort((a, b) => a - b);
      const grupos = new Map(), itens = [];
      for (const id of ids) {
        const c = coments.get(id);
        let fora;
        try { fora = JSON.parse(c.corpo); } catch (e) { continue; }
        if (!fora || fora.t1 !== ESQUEMA) continue;
        if (fora.g) {
          let g = grupos.get(fora.g);
          if (!g) { g = { primeiro: c, partes: [], total: fora.p[1] }; grupos.set(fora.g, g); itens.push({ grupo: g }); }
          g.partes[fora.p[0]] = { d: fora.d, c };
          continue;
        }
        itens.push({ c, fora });
      }
      const E = novoEstado();
      const hashes = new Map(), ultimo = new Map(), vistos = new Set();
      this._integridade = [];
      let regrasNovas = false;
      const eu = this._eu();
      const marcar = (n, t, texto) => {
        this._integridade.push({ n, texto });
        const c = E.casos.get(n);
        if (c && !c._alertado) { c._alertado = true; tl(c, t, 'Atenção: um registro deste caso foi alterado ou removido fora do sistema TIC1'); }
      };
      // Junta as partes e, numa passada prévia, abre todas as chaves entregues a mim: uma chave reentregue
      // depois (recuperação de acesso, especialista novo) precisa valer para os eventos anteriores.
      const resolvidos = [];
      for (const it of itens) {
        let c = it.c, fora = it.fora;
        if (it.grupo) {
          const g = it.grupo;
          if (g.partes.filter(Boolean).length !== g.total) continue;
          c = g.primeiro;
          try { fora = JSON.parse(g.partes.map(p => p.d).join('')); } catch (e) { continue; }
          c = Object.assign({}, c, { editado: g.partes.some(p => p.c.editado), atualizado: g.partes.map(p => p.c.atualizado).join('|') });
        }
        if (fora.tp && fora.tp !== 'caso') continue;
        resolvidos.push({ c, fora });
        if (!this._cif) continue;
        for (const w of (fora.w || [])) {
          const chaveId = c.n + '|' + w.r;
          if (this._chaves.has(chaveId) || !w.p || !w.p[eu]) continue;
          try {
            const cru = await desembrulhar(w.p[eu], this._cif, ctxChave(c.n, w.r, eu));
            this._chaves.set(chaveId, { cru, chave: await aesImportar(cru) });
          } catch (e) { /* embrulho para uma chave antiga minha: ignorado */ }
        }
      }
      for (const { c, fora } of resolvidos) {
        const n = c.n;
        // O encadeamento usa o hash do texto cifrado: todos calculam igual, mesmo sem a chave.
        const hs = hashes.get(n) || new Set();
        hashes.set(n, hs);
        const hOut = await hashFora(fora);
        const anteriores = new Set(hs);
        hs.add(hOut); ultimo.set(n, hOut);
        const kc = this._chaves.get(n + '|' + fora.k);
        if (!kc) continue;
        const cacheId = c.id + '|' + c.atualizado;
        let r = this._dec.get(cacheId);
        if (!r) {
          r = { ok: false };
          try {
            let pt = await aesDecifrar(kc.chave, deb64u(fora.iv), deb64u(fora.c), aadEvento(n, fora.k));
            if (fora.z) pt = await descomprimir(pt);
            const o = JSON.parse(decod.decode(pt));
            const pub = o.ev && await this._pubAss(o.ev.autor);
            r = { ok: !!(pub && o.ev.caso === n && await this._verificarAutor(pub, o.ev, o.sig, c.criado)), ev: o.ev, sig: o.sig, impressao: pub && pub.impressao };
          } catch (e) { r = { ok: false }; }
          this._dec.set(cacheId, r);
        }
        if (!r.ok) { marcar(n, c.criado, 'assinatura'); continue; }
        const ev = r.ev;
        if (vistos.has(ev.id)) continue;
        vistos.add(ev.id);
        if (ev.r > REGRAS) { regrasNovas = true; continue; }
        for (const a of (ev.ant || [])) if (!anteriores.has(a)) { marcar(n, c.criado, 'ausente'); break; }
        let autor;
        if (ev.autor === COORD) autor = { login: COORD, perfil: 'coordenacao', nome: 'Coordenação TIC1', curto: 'Coordenação' };
        else {
          autor = this.usuarioDir(ev.autor);
          if (!autor || (autor.desativadoEm && c.criado.toISOString() > autor.desativadoEm)) continue;
        }
        const destinatarios = [];
        for (const w of (fora.w || [])) if (w.r === 'K1' && w.p) destinatarios.push.apply(destinatarios, Object.keys(w.p));
        const ctx = { u: autor, t: c.criado, cid: c.id, n, rotulo: fora.k, destinatarios, sig: r.sig, impressaoAutor: r.impressao };
        const falha = await conferir(E, ev, ctx, true);
        if (falha) continue;
        if (ev.tipo === 'sinal' && !this._sinaisVistos.has(ev.id)) {
          this._sinaisVistos.add(ev.id);
          this._sinais.push({ id: ev.id, n, caso: E.casos.get(n).id, autor: ev.autor, t: c.criado, dados: ev.dados });
          for (const f of this._ouvSinal) { try { f(this._sinais[this._sinais.length - 1]); } catch (e) { /* ouvinte */ } }
        }
      }
      this._E = E; this._hashes = hashes; this._ultimo = ultimo; this._regrasNovas = regrasNovas;
    }

    estado() {
      if (!this.usuario) return { cases: [], agenda: [], notifs: [] };
      const lidas = this._lidas;
      return estadoPara(this._E, this.usuario, this.agora(), n => !!lidas[n.id] && lidas[n.id] >= new Date(n.em).toISOString());
    }
    _casoPorId(id) {
      for (const c of this._E.casos.values()) if (c.id === id) return c;
      return null;
    }
    presenca(casoId) {
      const c = this._casoPorId(casoId);
      const s = c && this._E.salas.get(c.n);
      return { presentes: s ? Array.from(s.presentes, x => ({ login: x[0], sessao: x[1] })) : [], rec: s ? Array.from(s.rec) : [] };
    }
    aoSinal(fn) { this._ouvSinal.add(fn); return () => this._ouvSinal.delete(fn); }

    // ----- escrita de eventos

    _novoEvento(tipo, n, dados) {
      return { v: ESQUEMA, r: REGRAS, tipo, caso: n, autor: this._eu(), em: this.agora().toISOString(), id: idAleatorio(16), ant: this._ultimo.has(n) ? [this._ultimo.get(n)] : [], dados: dados || {} };
    }
    async _publicar(n, rotulo, ev, embrulhos, o) {
      const kc = this._chaves.get(n + '|' + rotulo);
      if (!kc) throw erro('chave', 'Sem a chave deste caso.');
      const s = await selarEvento({ n, rotulo, chave: kc.chave, ev, priv: this._ass, embrulhos });
      const partesC = dividir(s.corpo);
      let ultimoC = null;
      for (const p of partesC) {
        const c = await this._gh.comentar(n, p, o);
        ultimoC = c;
        if (c && c.id) this._coment.set(c.id, { id: c.id, n, criado: new Date(c.created_at), atualizado: c.updated_at, corpo: c.body || p, editado: false });
      }
      await this._recalcular();
      this._mudou();
      return ultimoC;
    }
    _rotuloAtual(c) { return c._k2 && this._chaves.has(c.n + '|' + c._k2) ? c._k2 : 'K1'; }
    async _preconferir(n, ev, extra) {
      const ctx = Object.assign({ u: this.usuario, t: this.agora(), cid: 0, n, rotulo: 'K1', destinatarios: [] }, extra || {});
      if (!SEM_CASO[ev.tipo]) { const c = this._E.casos.get(n); if (c) ctx.rotulo = extra && extra.rotulo || this._rotuloAtual(c); }
      const falha = await conferir(this._E, ev, ctx, false);
      if (falha) throw erro('regra', falha);
    }
    _exigirEscrita() {
      if (this._regrasNovas) throw erro('versao', 'Há uma versão mais nova do TIC1. Recarregue a página antes de continuar.');
      if (!this.usuario || !this._gh) throw erro('sessao', 'Sua sessão terminou. Entre novamente.');
    }
    async _subirArquivos(arquivos) {
      const meta = [];
      for (const a of (arquivos || [])) {
        const nome = limpo(String(a.nome || '').split(/[\\/]/).pop(), 120);
        const dados = a.dados instanceof Uint8Array ? a.dados : deb64(a.conteudo || '');
        meta.push({ nome, bytes: dados.length, caminho: 'anexos/' + idAleatorio(24) + '.bin', dados });
      }
      const ea = validarArquivos(meta.map(m => Object.assign({}, m, { kf: 'x', iv: 'x', sha: '0'.repeat(64) })));
      if (ea) throw erro('regra', ea);
      const saida = [];
      for (const m of meta) {
        const kf = aleatorio(32);
        const chave = await aesImportar(kf);
        const r = await aesCifrar(chave, m.dados, 'tic1-anexo|' + m.caminho);
        await this._gh.gravarArquivo(m.caminho, concat(r.iv, r.ct));
        saida.push({ nome: m.nome, bytes: m.bytes, caminho: m.caminho, kf: b64u(kf), iv: b64u(r.iv), sha: hex(await sha256(m.dados)) });
      }
      return saida;
    }

    // Mesmo contrato do antigo POST /api/acao: devolve {ok, caso?, rnds?} ou lança Error com a mensagem.
    async acao(tipo, d) {
      d = d || {};
      if (tipo === 'lerNotifs' || tipo === 'lerNotif') return this._marcarLidas(tipo === 'lerNotif' ? d.notif : null);
      this._exigirEscrita();
      const u = this.usuario;
      if (tipo === 'criar') {
        const novo = Object.assign({}, d.novo || {});
        const arquivos = novo.arquivos; delete novo.arquivos; delete novo.anexos;
        const prova = this._novoEvento('criar', 0, { novo, arquivos: [] });
        await this._preconferir(-1, prova);
        const metas = await this._subirArquivos(arquivos);
        const issue = await this._gh.criarIssue('caso');
        const n = issue.number;
        const cru = aleatorio(32);
        this._chaves.set(n + '|K1', { cru, chave: await aesImportar(cru) });
        const destinos = [{ login: u.login, cif: u.cif }].concat(this.especialistasAtivos().filter(x => x.login !== u.login).map(x => ({ login: x.login, cif: x.cif })));
        if (this.dir.coordenacao) destinos.push({ login: COORD, cif: this.dir.coordenacao.cif });
        const ev = this._novoEvento('criar', n, { novo, arquivos: metas });
        await this._publicar(n, 'K1', ev, [await embrulhosPara(cru, n, 'K1', destinos)]);
        const c = this._E.casos.get(n);
        if (!c) throw erro('regra', 'A solicitação foi enviada, mas não apareceu no registro. Recarregue a página.');
        return { ok: true, caso: c.id };
      }
      const c = this._casoPorId(d.caso);
      if (!c || !podeVer(c, u)) throw erro('regra', 'Caso não encontrado ou sem acesso (RN19).');
      const n = c.n;
      let ev, rotulo = this._rotuloAtual(c), embrulhos;
      switch (tipo) {
        case 'aceitar': {
          const k2 = 'K2:' + idAleatorio(16);
          ev = this._novoEvento('aceitar', n, { k2 });
          await this._preconferir(n, ev, { rotulo: 'K1' });
          const cru = aleatorio(32);
          this._chaves.set(n + '|' + k2, { cru, chave: await aesImportar(cru) });
          const sol = this.usuarioDir(c.solicitanteLogin);
          const destinos = [{ login: u.login, cif: u.cif }];
          if (sol) destinos.push({ login: sol.login, cif: sol.cif });
          if (this.dir.coordenacao) destinos.push({ login: COORD, cif: this.dir.coordenacao.cif });
          embrulhos = [await embrulhosPara(cru, n, k2, destinos)];
          rotulo = 'K1';
          await this._publicar(n, rotulo, ev, embrulhos);
          await esperar(this.esperaAceite);
          try { await this.sincronizar(); } catch (e) { /* confere na próxima sondagem */ }
          const depois = this._E.casos.get(n);
          if (!depois || depois.especialistaLogin !== u.login) throw erro('regra', 'Este caso acabou de ser aceito por outro especialista.');
          return { ok: true };
        }
        case 'recusar': ev = this._novoEvento('recusar', n, { motivo: d.motivo, texto: d.texto }); break;
        case 'agendar': ev = this._novoEvento('agendar', n, { data: d.data, hora: d.hora, obs: d.obs }); break;
        case 'cancelarReuniao': ev = this._novoEvento('cancelarReuniao', n, {}); break;
        case 'mensagem': ev = this._novoEvento('mensagem', n, { texto: d.texto }); break;
        case 'parecer': ev = this._novoEvento('parecer', n, { parecer: d.parecer }); break;
        case 'rnds': ev = this._novoEvento('rnds', n, {}); break;
        case 'anexar': {
          await this._preconferir(n, this._novoEvento('anexar', n, { arquivos: [{ nome: 'x.pdf', bytes: 1, caminho: 'anexos/' + 'a'.repeat(20) + '.bin', kf: 'x', iv: 'x', sha: '0'.repeat(64) }] }));
          const metas = await this._subirArquivos(d.arquivos);
          ev = this._novoEvento('anexar', n, { arquivos: metas });
          break;
        }
        default: throw erro('regra', 'Ação desconhecida.');
      }
      await this._preconferir(n, ev, { rotulo });
      await this._publicar(n, rotulo, ev, embrulhos);
      const res = { ok: true };
      if (tipo === 'rnds') { const cc = this._E.casos.get(n); res.rnds = cc && cc.rnds; }
      return res;
    }
    async _marcarLidas(id) {
      const st = this.estado();
      for (const n of st.notifs) {
        if (id && n.id !== id) continue;
        const orig = this._E.notifs.find(x => x.id === n.id);
        if (orig) this._lidas[n.id] = new Date(orig.em).toISOString();
      }
      if (this.usuario) await this.arm.set('lidas:' + this.usuario.login, this._lidas);
      this._mudou();
      return { ok: true };
    }

    // ----- chamada (usado por tic1-chamada.js)

    async eventoSala(casoId, tipo, dados, o) {
      this._exigirEscrita();
      const c = this._casoPorId(casoId);
      if (!c) throw erro('regra', 'Caso não encontrado ou sem acesso (RN19).');
      const rotulo = this._rotuloAtual(c);
      const ev = this._novoEvento(tipo, c.n, dados);
      await this._preconferir(c.n, ev, { rotulo });
      return this._publicar(c.n, rotulo, ev, null, o);
    }

    // ----- gravações cifradas
    async prepararGravacao(casoId, dados, mime) {
      const c = this._casoPorId(casoId);
      if (!c) throw erro('regra', 'Caso não encontrado ou sem acesso (RN19).');
      const r = await gravacaoCifrar(dados, { caso: casoId, mime });
      return { partes: r.partes, evento: { rid: r.rid, kr: r.kr, mime, sha256: hex(await sha256(dados)), bytes: dados.length } };
    }
    async abrirGravacao(bytes) {
      bytes = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      const cab = gravacaoCabecalho(bytes);
      for (const c of this._E.casos.values()) {
        const g = (c._gravacoes || []).find(x => x.rid === cab.rid);
        if (!g) continue;
        if (!podeVer(c, this.usuario)) break;
        const r = await gravacaoDecifrar(bytes, g.kr);
        let total = 0; for (const p of r.partes) total += p.length;
        const tudo = new Uint8Array(total); let o = 0; for (const p of r.partes) { tudo.set(p, o); o += p.length; }
        if (g.sha && hex(await sha256(tudo)) !== g.sha) throw erro('gravacao', 'A gravação não confere com o SHA-256 registrado no caso.');
        this._auditar('GRAVACAO_ABERTA', { caso: c.id, rid: cab.rid });
        return { dados: tudo, mime: r.mime, caso: c.id };
      }
      throw erro('gravacao', 'Esta gravação não pertence a nenhum caso que você possa ver (RN19).');
    }

    // ----- anexos

    async abrirAnexo(url) {
      const m = /^tic1:(\d+):(\d+)$/.exec(String(url || ''));
      if (!m) throw erro('anexo', 'Anexo não encontrado.');
      const c = this._E.casos.get(Number(m[1]));
      if (!c || !podeVer(c, this.usuario)) throw erro('anexo', 'Sem acesso a este caso.');
      const a = c.anexos[Number(m[2])];
      if (!a || !a._arq) throw erro('anexo', 'Este é um anexo de exemplo, sem arquivo real.');
      const bruto = await this._gh.lerArquivo(a._arq.caminho);
      const chave = await aesImportar(deb64u(a._arq.kf));
      const dados = await aesDecifrar(chave, bruto.subarray(0, 12), bruto.subarray(12), 'tic1-anexo|' + a._arq.caminho);
      if (hex(await sha256(dados)) !== a._arq.sha) throw erro('anexo', 'O arquivo não confere com o registrado (SHA-256).');
      const ext = extensao(a.nome);
      const mime = MIME_NA_TELA[ext] || 'application/octet-stream';
      this._auditar('ANEXO_ABERTO', { caso: c.id, nome: a.nome });
      return { dados, nome: a.nome, mime, naTela: !!MIME_NA_TELA[ext] };
    }

    // ----- senha, auditoria

    async _abrirMeuCofre(senha, usarPasskey) {
      const u = this.usuario, ent = await this._entrada(u.login);
      const cofres = await this._cofresDe(u.login, ent);
      let fator;
      const kitNorm = await this.arm.get('kit:' + u.login);
      if (kitNorm && !usarPasskey) fator = { tipo: 'kit', segredo: lerChaveSecreta(kitNorm) };
      else {
        const lista = [];
        for (const cf of cofres) for (const pk of passkeysDoCofre(cf)) if (!lista.some(x => x.id === pk.id)) lista.push(pk);
        if (!lista.length || !passkey.suportado()) throw erro('kit', 'Este aparelho não guardou a chave secreta. Saia e entre de novo informando o Kit de acesso.');
        const r = await passkey.obter(lista);
        fator = { tipo: 'passkey', id: r.id, segredo: r.segredo };
      }
      for (const cf of cofres) {
        const ab = await abrirCofre(cf, u.login, senha, fator, true);
        if (ab) return { ab, cofre: cf, kit: fator.tipo === 'kit' ? fator.segredo : null };
      }
      throw erro('senha', 'Senha atual incorreta.');
    }
    async _pedidoCofre(cofre) {
      await this.arm.set('cofre:' + this.usuario.login, cofre);
      const n = this.cfg.dados && this.cfg.dados.issues && this.cfg.dados.issues.pedidos;
      if (!n) return false;
      const ped = { tipo: 'cofre', login: this.usuario.login, cofre, em: this.agora().toISOString() };
      const sig = await assinar(this._ass, ped);
      await this._gh.comentar(n, JSON.stringify({ t1: ESQUEMA, tp: 'ped2', ped, sig }));
      return true;
    }
    async trocarSenha(atual, nova) {
      this._exigirEscrita();
      const u = this.usuario;
      const fraca = senhaFraca(nova, u.login);
      if (fraca) throw erro('senha', fraca);
      const m = await this._abrirMeuCofre(atual);
      if (m.cofre.v !== 2 && !m.kit) throw erro('kit', 'Para trocar a senha deste cofre antigo, entre com o Kit de acesso.');
      const r = await fecharCofreFm({ login: u.login, senha: nova, assPkcs8: m.ab.assPkcs8, cifPkcs8: m.ab.cifPkcs8, fm: m.ab.fm || undefined,
        fechaduras: m.cofre.v === 2 ? m.cofre.f : [], kit: m.cofre.v === 2 ? null : m.kit, iter: this.iter });
      await this._pedidoCofre(r.cofre);
      this._auditar('SENHA_TROCADA', {});
      return { ok: true };
    }
    // A passkey é criada primeiro (o navegador exige que isso aconteça logo depois do clique).
    async adicionarPasskey(senha, nomeAparelho) {
      this._exigirEscrita();
      if (!passkey.suportado()) throw erro('passkey-prf', 'Este navegador não oferece passkeys.');
      const u = this.usuario;
      const pk = await passkey.criar(u.login, u.nome);
      const m = await this._abrirMeuCofre(senha);
      let base = m.cofre, fm = m.ab.fm;
      if (base.v !== 2) {
        const r = await fecharCofreFm({ login: u.login, senha, assPkcs8: m.ab.assPkcs8, cifPkcs8: m.ab.cifPkcs8, kit: m.kit, iter: this.iter });
        base = r.cofre; fm = r.fm;
      }
      const f = await fechadura('passkey', pk.segredo, fm, u.login, { id: pk.id, prf: pk.prf, nome: limpo(nomeAparelho || 'passkey', 60) });
      const cofre = Object.assign({}, base, { f: (base.f || []).concat([f]), em: this.agora().toISOString() });
      await this._pedidoCofre(cofre);
      this._auditar('PASSKEY_ATIVADA', { nome: f.nome });
      return { ok: true };
    }
    // Devolve o texto do QR do Kit de acesso (para levar a outro aparelho), depois de conferir a senha.
    async qrDoKit(senha) {
      const kitNorm = await this.arm.get('kit:' + this.usuario.login);
      if (!kitNorm) throw erro('kit', 'Este aparelho não guardou a chave secreta (você entrou sem "lembrar este aparelho" ou com passkey).');
      await this._abrirMeuCofre(senha);
      return kitParaQr(this.usuario.login, kitNorm);
    }
    _auditar(tipo, dados) {
      try {
        const n = this.cfg.dados && this.cfg.dados.issues && this.cfg.dados.issues.auditoria;
        if (!n || !this.dir.coordenacao || !this._gh || this._modoCoord) return;
        const reg = { tipo, autor: this.usuario.login, em: this.agora().toISOString(), id: idAleatorio(12), dados };
        assinar(this._ass, reg)
          .then(sig => embrulhar(codif.encode(canon({ reg, sig })), this.dir.coordenacao.cif, 'auditoria'))
          .then(w => this._gh.comentar(n, JSON.stringify({ t1: ESQUEMA, tp: 'aud', w })))
          .catch(() => {});
      } catch (e) { /* auditoria nunca impede o uso */ }
    }

    // ----- coordenação (ferramenta de administração)

    async modoCoordenacao(chaves, gh) {
      this._reiniciarDados();
      this._modoCoord = true;
      this._ass = chaves.assPriv; this._cif = chaves.cifPriv;
      this.usuario = { login: COORD, perfil: 'coordenacao', nome: 'Coordenação TIC1', curto: 'Coordenação' };
      this._gh = gh;
    }
    modoLeitor(gh) {
      this._reiniciarDados();
      this._modoCoord = true; this._ass = null; this._cif = null;
      this.usuario = { login: COORD, perfil: 'coordenacao', nome: 'Leitor', curto: 'Leitor' };
      this._gh = gh;
    }
    // Pedidos de troca de cofre (senha nova, passkey nova) assinados pelo próprio usuário.
    async pedidosCofre() {
      const saida = [];
      for (const c of Array.from(this._coment.values()).sort((a, b) => a.id - b.id)) {
        let fora;
        try { fora = JSON.parse(c.corpo); } catch (e) { continue; }
        if (!fora || fora.tp !== 'ped2' || !fora.ped) continue;
        const ped = fora.ped, pub = await this._pubAss(ped.login);
        const valido = !!(pub && ped.tipo === 'cofre' && ped.cofre && ped.cofre.v === 2 && Array.isArray(ped.cofre.f) && ped.cofre.f.length &&
          await this._verificarAutor(pub, ped, fora.sig, c.criado));
        saida.push({ comentario: c.id, criado: c.criado.toISOString(), valido, ped });
      }
      return saida;
    }
    casosInternos() { return Array.from(this._E.casos.values()); }
    chaveCrua(n, rotulo) { const k = this._chaves.get(n + '|' + rotulo); return k ? k.cru : null; }
    async publicarExemplo(snapshot, extra) {
      const issue = await this._gh.criarIssue('caso');
      const n = issue.number;
      const destinos = extra.destinos;
      const cru = aleatorio(32);
      const rotulo = extra.k2 ? 'K2:' + idAleatorio(16) : 'K1';
      this._chaves.set(n + '|' + rotulo, { cru, chave: await aesImportar(cru) });
      const ev = this._novoEvento('exemplo', n, { caso: snapshot, k2: extra.k2 ? rotulo : null, agenda: extra.agenda || [], notifs: extra.notifs || [] });
      await this._publicar(n, rotulo, ev, [await embrulhosPara(cru, n, rotulo, destinos)]);
      return this._E.casos.get(n);
    }
    async reentregarFila(destinos) {
      let total = 0;
      for (const c of this._E.casos.values()) {
        if (c.status !== 'aguardando' || c.especialistaLogin) continue;
        const cru = this.chaveCrua(c.n, 'K1');
        if (!cru) continue;
        const w = await embrulhosPara(cru, c.n, 'K1', destinos);
        const ev = this._novoEvento('chaves', c.n, {});
        const s = await selarEvento({ n: c.n, rotulo: 'K1', chave: this._chaves.get(c.n + '|K1').chave, ev, priv: this._ass, embrulhos: [w] });
        await this._gh.comentar(c.n, s.corpo);
        total++;
      }
      return total;
    }
    async reentregarUsuario(login, cif) {
      const u = this.usuarioDir(login);
      if (!u) throw erro('regra', 'Usuário não encontrado no diretório.');
      let total = 0;
      for (const c of this._E.casos.values()) {
        const rotulos = [];
        if (vinculado(c, login)) { rotulos.push('K1'); if (c._k2) rotulos.push(c._k2); }
        else if (u.perfil === 'especialista' && c.status === 'aguardando' && !c.especialistaLogin) rotulos.push('K1');
        const w = [];
        for (const r of rotulos) { const cru = this.chaveCrua(c.n, r); if (cru) w.push(await embrulhosPara(cru, c.n, r, [{ login, cif }])); }
        if (!w.length) continue;
        const rotulo = c._k2 && this.chaveCrua(c.n, c._k2) ? c._k2 : 'K1';
        const ev = this._novoEvento('chaves', c.n, {});
        const sl = await selarEvento({ n: c.n, rotulo, chave: this._chaves.get(c.n + '|' + rotulo).chave, ev, priv: this._ass, embrulhos: w });
        await this._gh.comentar(c.n, sl.corpo);
        total++;
      }
      return total;
    }
    // orig: {id, n, criado, atualizado, corpo} de um comentário apagado ou alterado (vem do backup)
    async restaurarComentario(orig) {
      const o = { id: orig.id, n: orig.n, criado: orig.criado, atualizado: orig.atualizado, corpo: orig.corpo };
      const sig = await assinar(this._ass, o);
      return this._gh.comentar(o.n, JSON.stringify({ t1: ESQUEMA, tp: 'rest', orig: o, sig }));
    }
    async lerPrivados(tipo) {
      // Auditoria ('aud') e pedidos ('ped'): só a coordenação decifra.
      const saida = [];
      for (const c of Array.from(this._coment.values()).sort((a, b) => a.id - b.id)) {
        let fora;
        try { fora = JSON.parse(c.corpo); } catch (e) { continue; }
        if (!fora || fora.tp !== tipo || !fora.w) continue;
        try {
          const o = JSON.parse(decod.decode(await desembrulhar(fora.w, this._cif, tipo === 'aud' ? 'auditoria' : 'pedido')));
          const corpo = o.reg || o.ped;
          const pub = await this._pubAss(corpo.autor || corpo.login);
          saida.push({ comentario: c.id, criado: c.criado.toISOString(), valido: !!(pub && await this._verificarAutor(pub, corpo, o.sig, c.criado)), dados: corpo });
        } catch (e) { saida.push({ comentario: c.id, criado: c.criado.toISOString(), valido: false }); }
      }
      return saida;
    }
  }
  regras.chaves = async function (E, ev, ctx) { return ctx.u.login === COORD ? null : 'Somente a coordenação reentrega chaves.'; };

  // ---------------------------------------------------------------- cadastro por convite

  const cadastro = {
    async preparar(o) {
      const login = String(o.login || '').trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9._-]{1,31}$/.test(login)) throw erro('login', 'Login inválido.');
      const fraca = senhaFraca(o.senha, login);
      if (fraca) throw erro('senha', fraca);
      const fm = aleatorio(32);
      const pk = o.passkey ? await passkey.criar(login, o.nome) : null;
      const id = await gerarIdentidade();
      const kitTxt = chaveSecretaNova();
      const r = await fecharCofreFm({ login, senha: o.senha, kit: lerChaveSecreta(kitTxt), assPriv: id.assPriv, cifPriv: id.cifPriv, iter: o.iter, fm });
      if (pk) r.cofre.f.push(await fechadura('passkey', pk.segredo, fm, login, { id: pk.id, prf: pk.prf, nome: limpo(o.nomeAparelho || 'passkey do cadastro', 60) }));
      const ass = await pubRaw(id.assPub), cif = await pubRaw(id.cifPub);
      const campos = { v: 1, login, ass, cif, cofre: r.cofre };
      const mac = await hmac(String(o.convite || ''), canon(campos));
      const pedido = 'TIC1-CADASTRO.' + b64u(codif.encode(canon(Object.assign({ mac }, campos))));
      return { login, kit: kitTxt, qr: kitParaQr(login, kitTxt), pedido, impressao: await impressao(ass, cif), passkey: !!pk };
    },
    async lerPedido(texto, convite) {
      const s = String(texto || '').trim().replace(/\s+/g, '');
      if (!s.startsWith('TIC1-CADASTRO.')) throw erro('pedido', 'Pedido de cadastro inválido.');
      const o = JSON.parse(decod.decode(deb64u(s.slice('TIC1-CADASTRO.'.length))));
      const mac = o.mac; delete o.mac;
      if (mac !== await hmac(String(convite || ''), canon(o))) throw erro('pedido', 'O pedido não confere com o código do convite.');
      await importarPubAss(o.ass); await importarPubCif(o.cif);
      return Object.assign(o, { impressao: await impressao(o.ass, o.cif) });
    }
  };

  return {
    VERSAO, ESQUEMA, REGRAS, COORD, FUSO, ITER_PADRAO,
    Cliente, GitHubDados, cadastro, passkey,
    armazenamentoMemoria, armazenamentoNavegador,
    cripto: { gerarIdentidade, pubRaw, privPkcs8, importarPrivAss, importarPrivCif, importarPubAss, importarPubCif, pubDaPriv, impressao,
      fecharCofre, abrirCofre, embrulhar, desembrulhar, assinar, verificar, sha256, hex, b64, deb64, b64u, deb64u, aleatorio, idAleatorio,
      canon, chaveSecretaNova, lerChaveSecreta, normalizarKit, jwtApp, pemParaDer, aesImportar, aesCifrar, aesDecifrar,
      fecharCofreFm, fechadura, passkeysDoCofre, kitParaQr, lerQrKit, idLogin, diretorioPublico, abrirDiretorio, gravacaoCifrar, gravacaoDecifrar, gravacaoCabecalho },
    regras: { novoEstado, conferir, estadoPara, podeVer, vinculado, idDoCaso, CONDS },
    texto: { completarExibicao, senhaFraca, limpo, tamanhoLegivel, duracaoLegivel, fmtDataHora, fmtTL, fmtDM, isoDia, rotuloAgenda, rotuloCriada, rotuloRelativo, extensao }
  };
});
