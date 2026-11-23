/*
 * TIC1 — gerador de QR code sem dependências (modo byte, versões 1 a 10, correção de erro M).
 * Usado para o Kit de acesso: o texto cabe com folga (até 213 bytes na versão 10).
 */
(function (raiz, fabrica) {
  const Q = fabrica();
  if (typeof module === 'object' && module.exports) module.exports = Q;
  else raiz.TIC1QR = Q;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // [total de codewords, codewords de correção por bloco, [blocos, dados por bloco]...]
  const BLOCOS_M = [null,
    [26, 10, [1, 16]], [44, 16, [1, 28]], [70, 26, [1, 44]], [100, 18, [2, 32]], [134, 24, [2, 43]],
    [172, 16, [4, 27]], [196, 18, [4, 31]], [242, 22, [2, 38], [2, 39]], [292, 22, [3, 36], [2, 37]], [346, 26, [4, 43], [1, 44]]];
  const ALINHAMENTO = [null, [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50]];
  const INFO_VERSAO = { 7: 0x07C94, 8: 0x085BC, 9: 0x09A99, 10: 0x0A4D3 };

  // ----- GF(256) e Reed-Solomon
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () { let x = 1; for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11D; } for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255]; })();
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  function gerador(n) {
    let g = [1];
    for (let i = 0; i < n; i++) {
      const nova = new Array(g.length + 1).fill(0);
      for (let j = 0; j < g.length; j++) { nova[j] ^= g[j]; nova[j + 1] ^= mul(g[j], EXP[i]); }
      g = nova;
    }
    return g;
  }
  function correcao(dados, n) {
    const g = gerador(n), r = dados.concat(new Array(n).fill(0));
    for (let i = 0; i < dados.length; i++) {
      const c = r[i];
      if (c) for (let j = 0; j < g.length; j++) r[i + j] ^= mul(g[j], c);
    }
    return r.slice(dados.length);
  }

  // ----- codificação dos dados
  function bytesUtf8(t) { return Array.from(new TextEncoder().encode(t)); }
  function capacidade(v) { const b = BLOCOS_M[v]; let d = 0; for (let k = 2; k < b.length; k++) d += b[k][0] * b[k][1]; return d; }
  function codewords(dados, v) {
    const bits = [];
    const poe = (val, n) => { for (let i = n - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
    poe(4, 4);
    poe(dados.length, v < 10 ? 8 : 16);
    for (const b of dados) poe(b, 8);
    const cap = capacidade(v) * 8;
    for (let i = 0; i < 4 && bits.length < cap; i++) bits.push(0);
    while (bits.length % 8) bits.push(0);
    const cw = [];
    for (let i = 0; i < bits.length; i += 8) { let x = 0; for (let j = 0; j < 8; j++) x = (x << 1) | bits[i + j]; cw.push(x); }
    for (let p = 0; cw.length < capacidade(v); p++) cw.push(p % 2 ? 0x11 : 0xEC);
    const b = BLOCOS_M[v], blocos = [];
    let pos = 0;
    for (let k = 2; k < b.length; k++) for (let i = 0; i < b[k][0]; i++) { const d = cw.slice(pos, pos + b[k][1]); pos += b[k][1]; blocos.push({ d, e: correcao(d, b[1]) }); }
    const saida = [], maxD = Math.max.apply(null, blocos.map(x => x.d.length));
    for (let i = 0; i < maxD; i++) for (const bl of blocos) if (i < bl.d.length) saida.push(bl.d[i]);
    for (let i = 0; i < b[1]; i++) for (const bl of blocos) saida.push(bl.e[i]);
    return saida;
  }

  // ----- matriz
  function base(v) {
    const n = 17 + 4 * v;
    const m = [], res = [];
    for (let i = 0; i < n; i++) { m.push(new Array(n).fill(0)); res.push(new Array(n).fill(false)); }
    const marca = (r, c, val) => { m[r][c] = val ? 1 : 0; res[r][c] = true; };
    const localizador = (r0, c0) => {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const rr = r0 + r, cc = c0 + c;
        if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue;
        const dentro = r >= 0 && r <= 6 && c >= 0 && c <= 6;
        const escuro = dentro && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
        marca(rr, cc, escuro);
      }
    };
    localizador(0, 0); localizador(0, n - 7); localizador(n - 7, 0);
    for (let i = 8; i < n - 8; i++) { marca(6, i, i % 2 === 0); marca(i, 6, i % 2 === 0); }
    const al = ALINHAMENTO[v];
    for (const r of al) for (const c of al) {
      if ((r === 6 && c === 6) || (r === 6 && c === al[al.length - 1]) || (r === al[al.length - 1] && c === 6)) continue;
      for (let dr = -2; dr <= 2; dr++) for (let dc = -2; dc <= 2; dc++) marca(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
    }
    marca(4 * v + 9, 8, true);
    for (let i = 0; i < 9; i++) { if (!res[8][i]) res[8][i] = true; if (!res[i][8]) res[i][8] = true; }
    for (let i = 0; i < 8; i++) { res[8][n - 1 - i] = true; res[n - 1 - i][8] = true; }
    if (v >= 7) {
      const info = INFO_VERSAO[v];
      for (let i = 0; i < 18; i++) {
        const bit = (info >>> i) & 1, a = Math.floor(i / 3), b = n - 11 + (i % 3);
        marca(a, b, bit); marca(b, a, bit);
      }
    }
    return { n, m, res };
  }
  function colocar(B, cw) {
    const { n, m, res } = B;
    let i = 0, subindo = true;
    for (let c = n - 1; c > 0; c -= 2) {
      if (c === 6) c--;
      for (let k = 0; k < n; k++) {
        const r = subindo ? n - 1 - k : k;
        for (let d = 0; d < 2; d++) {
          const cc = c - d;
          if (res[r][cc]) continue;
          const bit = i < cw.length * 8 ? (cw[i >>> 3] >>> (7 - (i & 7))) & 1 : 0;
          m[r][cc] = bit; i++;
        }
      }
      subindo = !subindo;
    }
  }
  const MASCARAS = [
    (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
    (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
    (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0, (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0];
  function formato(mascara) {
    const d = (0 << 3) | mascara;
    let rem = d;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    return ((d << 10) | rem) ^ 0x5412;
  }
  function aplicar(B, mascara) {
    const { n, res } = B, m = B.m.map(l => l.slice());
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (!res[r][c] && MASCARAS[mascara](r, c)) m[r][c] ^= 1;
    const f = formato(mascara), bit = i => (f >>> i) & 1;
    for (let i = 0; i <= 5; i++) m[i][8] = bit(i);
    m[7][8] = bit(6); m[8][8] = bit(7); m[8][7] = bit(8);
    for (let i = 9; i < 15; i++) m[8][14 - i] = bit(i);
    for (let i = 0; i < 8; i++) m[8][n - 1 - i] = bit(i);
    for (let i = 8; i < 15; i++) m[n - 15 + i][8] = bit(i);
    m[n - 8][8] = 1;
    return m;
  }
  function penalidade(m) {
    const n = m.length;
    let p = 0;
    for (let r = 0; r < n; r++) for (const linha of [m[r], m.map(l => l[r])]) {
      let cor = linha[0], seq = 1;
      for (let c = 1; c < n; c++) { if (linha[c] === cor) { seq++; if (seq === 5) p += 3; else if (seq > 5) p++; } else { cor = linha[c]; seq = 1; } }
      for (let c = 0; c + 10 < n; c++) {
        const s = linha.slice(c, c + 11).join('');
        if (s === '10111010000' || s === '00001011101') p += 40;
      }
    }
    for (let r = 0; r < n - 1; r++) for (let c = 0; c < n - 1; c++) { const v = m[r][c]; if (v === m[r][c + 1] && v === m[r + 1][c] && v === m[r + 1][c + 1]) p += 3; }
    let escuros = 0; for (const l of m) for (const v of l) escuros += v;
    p += Math.floor(Math.abs(escuros * 100 / (n * n) - 50) / 5) * 10;
    return p;
  }
  function matriz(texto) {
    const dados = bytesUtf8(texto);
    let v = 1;
    while (v <= 10 && capacidade(v) < dados.length + (v < 10 ? 2 : 3)) v++;
    if (v > 10) throw new Error('Texto longo demais para o QR code do TIC1.');
    const B = base(v);
    colocar(B, codewords(dados, v));
    let melhor = null, pMin = Infinity;
    for (let k = 0; k < 8; k++) { const m = aplicar(B, k), p = penalidade(m); if (p < pMin) { pMin = p; melhor = m; } }
    return melhor;
  }
  function svg(texto, o) {
    o = o || {};
    const m = matriz(texto), n = m.length, q = o.margem != null ? o.margem : 4, t = n + 2 * q;
    let caminho = '';
    for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (m[r][c]) caminho += 'M' + (c + q) + ' ' + (r + q) + 'h1v1h-1z';
    return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + t + ' ' + t + '" shape-rendering="crispEdges"><rect width="' + t + '" height="' + t + '" fill="#fff"/><path d="' + caminho + '" fill="#000"/></svg>';
  }
  function dataUrl(texto, o) { return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg(texto, o)); }
  return { matriz, svg, dataUrl };
});
