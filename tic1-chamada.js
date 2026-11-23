/*
 * TIC1 — videochamada 1:1 direta entre os navegadores (WebRTC P2P).
 *
 * Pela RN19 só a dupla vinculada ao caso entra na sala. O solicitante sempre faz a oferta.
 * A sinalização (oferta/resposta, com todas as rotas ICE já coletadas) vai cifrada pelo
 * registro de eventos do caso, via TIC1Nucleo. Depois de conectados, estado de microfone,
 * câmera, REC e saída passam pelo canal de dados do próprio WebRTC.
 */
(function (raiz, fabrica) {
  const C = fabrica();
  if (typeof module === 'object' && module.exports) module.exports = C;
  else raiz.TIC1Chamada = C;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const COLETA_MS = 3000;
  const ESPERA_RESPOSTA_MS = 25000;
  const MAX_TENTATIVAS = 4;
  const SINAL_VALIDO_MS = 120000;

  function idSessao() {
    const a = new Uint8Array(16); crypto.getRandomValues(a);
    return Array.from(a, x => 'abcdefghijkmnpqrstuvwxyz23456789'[x & 31]).join('');
  }
  function coletarRotas(pc) {
    if (pc.iceGatheringState === 'complete') return Promise.resolve();
    return new Promise(ok => {
      const fim = () => { pc.removeEventListener('icegatheringstatechange', ver); clearTimeout(t); ok(); };
      const ver = () => { if (pc.iceGatheringState === 'complete') fim(); };
      const t = setTimeout(fim, COLETA_MS);
      pc.addEventListener('icegatheringstatechange', ver);
    });
  }

  class Chamada {
    constructor(o) {
      this.cli = o.cliente;
      this.caso = o.casoId;
      this.eu = o.meuLogin;
      this.outro = o.outroLogin;
      this.ofertante = !!o.souOfertante;
      this.forcarTurn = !!o.forcarTurn;
      this.stream = o.stream || null;
      this.aoEvento = o.aoEvento || function () {};
      this.sessao = idSessao();
      this.pc = null; this.dc = null;
      this.remSessao = null; this.tentativa = 0; this.ofertaId = null;
      this.ativo = false; this.conectado = false;
      this.estadoLocal = { mic: true, cam: true, rec: false };
      this._desligar = [];
    }
    emitir(nome, dados) { try { this.aoEvento(nome, dados || {}); } catch (e) { console.warn('[TIC1] chamada', e); } }

    async iniciar() {
      this.ativo = true;
      this.emitir('fase', { fase: 'sinalizacao' });
      this._desligar.push(this.cli.aoSinal(s => this._sinal(s)));
      this._desligar.push(this.cli.aoMudar(() => this._presenca()));
      this.cli.modoRapido(true);
      await this.cli.eventoSala(this.caso, 'chamada-entrou', { sessao: this.sessao });
      this._aoSair = () => this.encerrar({ fechandoAba: true });
      if (typeof window !== 'undefined') window.addEventListener('pagehide', this._aoSair);
      this._presenca();
    }

    _presenca() {
      if (!this.ativo) return;
      const p = this.cli.presenca(this.caso);
      const eu = p.presentes.find(x => x.login === this.eu);
      if (eu && eu.sessao !== this.sessao) {
        this.emitir('erro', { msg: 'Sua conta entrou nesta sala em outra aba ou dispositivo.' });
        this.encerrar({ semAviso: true });
        return;
      }
      const rem = p.presentes.find(x => x.login === this.outro);
      if (!rem) {
        if (this.remSessao) {
          this.remSessao = null;
          this._fecharPc();
          this.emitir('saiu', { id: this.outro });
        }
        this.emitir('fase', { fase: this.conectado ? 'conectado' : 'aguardando' });
        return;
      }
      this.emitir('presente', { id: this.outro, rec: p.rec.includes(this.outro) });
      if (rem.sessao !== this.remSessao) {
        this.remSessao = rem.sessao;
        this._fecharPc();
        this.tentativa = 0;
        this.emitir('entrou', { id: this.outro });
        if (this.ofertante) this._ofertar();
        else this.emitir('fase', { fase: 'negociando' });
      }
    }

    _novoPc() {
      const pc = new RTCPeerConnection(Object.assign({ iceServers: this.cli.iceServers() }, this.forcarTurn ? { iceTransportPolicy: 'relay' } : {}));
      if (this.stream) this.stream.getTracks().forEach(t => pc.addTrack(t, this.stream));
      pc.ontrack = e => {
        const st = (e.streams && e.streams[0]) || new MediaStream([e.track]);
        this.remStream = st;
        e.track.onunmute = () => this.emitir('midia', {});
        e.track.onmute = () => this.emitir('midia', {});
        this.emitir('remoto', { id: this.outro, stream: st, kind: e.track.kind });
      };
      pc.onconnectionstatechange = () => {
        if (this.pc !== pc || !this.ativo) return;
        const cs = pc.connectionState;
        if (cs === 'connected') {
          this.conectado = true;
          clearTimeout(this._tResp);
          this.emitir('fase', { fase: 'conectado' });
          this.tipoConexao().then(t => this.emitir('conexao', t));
        } else if (cs === 'failed') {
          this.conectado = false;
          if (this.ofertante) this._ofertar(true);
          else this.emitir('fase', { fase: 'negociando' });
        } else if (cs === 'disconnected') {
          this.emitir('fase', { fase: 'instavel' });
        }
      };
      pc.ondatachannel = e => this._canal(e.channel);
      return pc;
    }
    _canal(dc) {
      this.dc = dc;
      dc.onopen = () => this._enviarCanal({ t: 'estado', ...this.estadoLocal });
      dc.onmessage = e => {
        let m; try { m = JSON.parse(e.data); } catch (x) { return; }
        if (m.t === 'estado') this.emitir('estado', { id: this.outro, mic: !!m.mic, cam: !!m.cam, rec: !!m.rec });
        else if (m.t === 'tchau') { this.remSessao = null; this._fecharPc(); this.emitir('saiu', { id: this.outro }); this.emitir('fase', { fase: 'aguardando' }); }
      };
    }
    _enviarCanal(m) { try { if (this.dc && this.dc.readyState === 'open') this.dc.send(JSON.stringify(m)); } catch (e) { /* canal fechado */ } }

    async _ofertar(reiniciar) {
      if (!this.ativo || !this.remSessao) return;
      if (++this.tentativa > MAX_TENTATIVAS) {
        this.emitir('fase', { fase: 'erro', erro: this.cli.temTurn()
          ? 'Não foi possível ligar os dois navegadores, nem pelo retransmissor. Verifique a conexão de internet e tente de novo.'
          : 'As duas redes não permitem conexão direta e o retransmissor (TURN) ainda não está configurado neste TIC1.' });
        return;
      }
      this.emitir('fase', { fase: 'negociando' });
      this._fecharPc();
      const pc = this.pc = this._novoPc();
      this._canal(pc.createDataChannel('tic1'));
      const oferta = await pc.createOffer({ iceRestart: !!reiniciar });
      await pc.setLocalDescription(oferta);
      await coletarRotas(pc);
      if (this.pc !== pc || !this.ativo) return;
      this.ofertaId = this.sessao + '.' + this.tentativa;
      await this.cli.eventoSala(this.caso, 'sinal', { tipo: 'oferta', para: this.outro, de: this.sessao, alvo: this.remSessao, id: this.ofertaId, sdp: pc.localDescription.sdp });
      clearTimeout(this._tResp);
      this._tResp = setTimeout(() => { if (this.pc === pc && !this.conectado) this._ofertar(true); }, ESPERA_RESPOSTA_MS);
    }

    async _sinal(s) {
      if (!this.ativo || s.caso !== this.caso || s.autor !== this.outro) return;
      const d = s.dados || {};
      if (d.para !== this.eu || d.alvo !== this.sessao) return;
      if (Date.now() - new Date(s.t).getTime() > SINAL_VALIDO_MS) return;
      try {
        if (d.tipo === 'oferta' && !this.ofertante) {
          if (this._ultimaOferta === d.id) return;
          this._ultimaOferta = d.id;
          this.remSessao = d.de;
          this._fecharPc();
          const pc = this.pc = this._novoPc();
          await pc.setRemoteDescription({ type: 'offer', sdp: d.sdp });
          await pc.setLocalDescription(await pc.createAnswer());
          await coletarRotas(pc);
          if (this.pc !== pc || !this.ativo) return;
          await this.cli.eventoSala(this.caso, 'sinal', { tipo: 'resposta', para: this.outro, de: this.sessao, alvo: d.de, id: d.id, sdp: pc.localDescription.sdp });
        } else if (d.tipo === 'resposta' && this.ofertante && d.id === this.ofertaId && this.pc && this.pc.signalingState === 'have-local-offer') {
          await this.pc.setRemoteDescription({ type: 'answer', sdp: d.sdp });
        }
      } catch (e) {
        console.warn('[TIC1] sinalização', e);
      }
    }

    enviarEstado(est) {
      Object.assign(this.estadoLocal, est);
      this._enviarCanal({ t: 'estado', ...this.estadoLocal });
    }
    trocarStream(stream) {
      this.stream = stream;
      if (!this.pc) return;
      for (const t of stream.getTracks()) {
        const s = this.pc.getSenders().find(x => x.track && x.track.kind === t.kind);
        if (s) s.replaceTrack(t);
      }
    }
    async tipoConexao() {
      const pc = this.pc;
      if (!pc) return { tipo: null, rtt: null };
      try {
        const rep = await pc.getStats();
        let par = null, selId = null;
        rep.forEach(r => { if (r.type === 'transport' && r.selectedCandidatePairId) selId = r.selectedCandidatePairId; });
        rep.forEach(r => { if (r.type === 'candidate-pair' && (r.id === selId || (!selId && r.nominated && r.state === 'succeeded'))) par = r; });
        if (!par) return { tipo: null, rtt: null };
        const loc = rep.get(par.localCandidateId), rem = rep.get(par.remoteCandidateId);
        const relay = (loc && loc.candidateType === 'relay') || (rem && rem.candidateType === 'relay');
        return { tipo: relay ? 'turn' : 'direta', rtt: par.currentRoundTripTime != null ? Math.round(par.currentRoundTripTime * 1000) : null };
      } catch (e) { return { tipo: null, rtt: null }; }
    }
    _fecharPc() {
      clearTimeout(this._tResp);
      if (this.dc) { try { this.dc.close(); } catch (e) { /* fechado */ } this.dc = null; }
      if (this.pc) { try { this.pc.close(); } catch (e) { /* fechado */ } this.pc = null; }
      this.conectado = false;
    }
    async encerrar(o) {
      o = o || {};
      if (!this.ativo) return;
      this.ativo = false;
      this._enviarCanal({ t: 'tchau' });
      this._desligar.forEach(f => f()); this._desligar = [];
      if (typeof window !== 'undefined' && this._aoSair) window.removeEventListener('pagehide', this._aoSair);
      this.cli.modoRapido(false);
      this._fecharPc();
      if (!o.semAviso) {
        try { await this.cli.eventoSala(this.caso, 'chamada-saiu', { sessao: this.sessao }, o.fechandoAba ? { keepalive: true } : undefined); }
        catch (e) { /* o redutor fecha a sala pela inatividade */ }
      }
    }
  }

  // ---------------------------------------------------------------- gravação local (RF13)

  // O relógio do desenho roda num Worker: requestAnimationFrame para em abas em segundo plano.
  function relogioWorker(fps, aoTique) {
    try {
      const src = 'let t=null;onmessage=e=>{clearInterval(t);if(e.data>0)t=setInterval(()=>postMessage(0),e.data)}';
      const url = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
      const w = new Worker(url);
      w.onmessage = aoTique;
      w.postMessage(Math.round(1000 / fps));
      return () => { w.postMessage(0); w.terminate(); URL.revokeObjectURL(url); };
    } catch (e) {
      const t = setInterval(aoTique, Math.round(1000 / fps));
      return () => clearInterval(t);
    }
  }

  class Gravador {
    constructor(o) {
      this.local = o.local; this.remoto = o.remoto; this.rotulo = o.rotulo || 'TIC1';
      this.nomeLocal = o.nomeLocal || ''; this.nomeRemoto = o.nomeRemoto || '';
      this.partes = []; this.inicio = 0; this.vr = null; this.vl = null;
    }
    static suportado() { return typeof MediaRecorder !== 'undefined' && typeof HTMLCanvasElement !== 'undefined' && !!HTMLCanvasElement.prototype.captureStream; }
    _video(stream) {
      const v = document.createElement('video');
      v.muted = true; v.playsInline = true; v.srcObject = stream;
      v.play().catch(() => {});
      return v;
    }
    _quadro(v, x, y, w, h, nome) {
      const g = this.g;
      g.fillStyle = '#16233a'; g.fillRect(x, y, w, h);
      if (v && v.videoWidth) {
        const r = Math.min(w / v.videoWidth, h / v.videoHeight);
        const vw = v.videoWidth * r, vh = v.videoHeight * r;
        g.drawImage(v, x + (w - vw) / 2, y + (h - vh) / 2, vw, vh);
      }
      if (nome) {
        g.fillStyle = 'rgba(0,0,0,.55)'; g.fillRect(x + 12, y + h - 40, Math.min(w - 24, 16 + nome.length * 10), 28);
        g.fillStyle = '#fff'; g.font = '600 17px system-ui, sans-serif'; g.fillText(nome, x + 20, y + h - 20);
      }
    }
    _desenhar() {
      const g = this.g, W = 1280, H = 720;
      g.fillStyle = '#0b1526'; g.fillRect(0, 0, W, H);
      this._quadro(this.vr, 16, 16, 832, H - 32, this.nomeRemoto);
      this._quadro(this.vl, 864, 16, 400, 300, this.nomeLocal);
      const dur = Math.floor((Date.now() - this.inicio) / 1000);
      g.fillStyle = '#c62828'; g.beginPath(); g.arc(884, 352, 8, 0, 7); g.fill();
      g.fillStyle = '#fff'; g.font = '700 18px system-ui, sans-serif';
      g.fillText('REC ' + String(Math.floor(dur / 60)).padStart(2, '0') + ':' + String(dur % 60).padStart(2, '0'), 902, 358);
      g.fillStyle = '#9fb3d1'; g.font = '15px system-ui, sans-serif';
      g.fillText(this.rotulo, 864, 392);
      g.fillText(new Date().toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }), 864, 416);
    }
    _ligarAudio(stream) {
      if (!this.ac || !this.dest || !stream || !stream.getAudioTracks().length) return;
      try { this.ac.createMediaStreamSource(stream).connect(this.dest); } catch (e) { /* sem áudio desta fonte */ }
    }
    // Quem entrar depois do início do REC também é gravado.
    definirRemoto(stream, nome) {
      if (!stream || stream === this.remoto) return;
      this.remoto = stream; if (nome) this.nomeRemoto = nome;
      this.vr = this._video(stream);
      this._ligarAudio(stream);
    }
    iniciar() {
      const cv = this.canvas = document.createElement('canvas');
      cv.width = 1280; cv.height = 720;
      this.g = cv.getContext('2d');
      this.vr = this.remoto ? this._video(this.remoto) : null;
      this.vl = this.local ? this._video(this.local) : null;
      this.inicio = Date.now();
      this._desenhar();
      this.pararRelogio = relogioWorker(15, () => this._desenhar());
      const saida = cv.captureStream(15);
      try {
        const AC = window.AudioContext || window.webkitAudioContext;
        this.ac = new AC();
        this.dest = this.ac.createMediaStreamDestination();
        this._ligarAudio(this.local);
        this._ligarAudio(this.remoto);
        this.dest.stream.getAudioTracks().forEach(t => saida.addTrack(t));
      } catch (e) { /* grava só o vídeo */ }
      const tipos = ['video/webm;codecs=vp8,opus', 'video/webm', 'video/mp4'];
      this.mime = tipos.find(t => MediaRecorder.isTypeSupported && MediaRecorder.isTypeSupported(t)) || '';
      this.mr = new MediaRecorder(saida, this.mime ? { mimeType: this.mime, videoBitsPerSecond: 1200000 } : undefined);
      this.mr.ondataavailable = e => { if (e.data && e.data.size) this.partes.push(e.data); };
      this.mr.start(5000);
    }
    parar() {
      return new Promise(ok => {
        const fim = async () => {
          if (this.pararRelogio) this.pararRelogio();
          if (this.ac) { try { this.ac.close(); } catch (e) { /* fechado */ } }
          const tipo = (this.mr && this.mr.mimeType) || this.mime || 'video/webm';
          const blob = new Blob(this.partes, { type: tipo });
          const buf = new Uint8Array(await blob.arrayBuffer());
          const sha = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)), b => b.toString(16).padStart(2, '0')).join('');
          ok({ blob, sha256: sha, bytes: buf.length, duracaoMs: Date.now() - this.inicio, ext: tipo.includes('mp4') ? 'mp4' : 'webm' });
        };
        if (!this.mr || this.mr.state === 'inactive') { fim(); return; }
        this.mr.onstop = fim;
        this.mr.stop();
      });
    }
  }

  return { Chamada, Gravador, idSessao };
});
