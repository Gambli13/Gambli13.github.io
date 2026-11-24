/*  note-share.js — live note sharing, used by index.html (owner) and note.html (link holders)
 *
 *  Firestore layout (enforced by firestore.rules):
 *    note_share_cfg/owner                     { proof }        owner passphrase proof, nobody can read it
 *    note_share_cfg/marker                    { setupAt }      only says "a passphrase has been set"
 *    note_share_owners/{uid}                  { proof, at }    devices that unlocked sharing
 *    note_shares/{shareId}                    { liveId, mode: 'view'|'edit', hasPassword, createdAt }   one per link
 *    note_shares/{shareId}/secret/pw          { hash }         nobody can read it, rules compare against it
 *    shared_notes/{liveId}                    { title, text, styles, imgs, imgW, rev, updatedAt, updatedBy }
 *    shared_notes/{liveId}/members/{uid}      { shareId, role, proof, at }    who got in, through which link
 *    shared_notes/{liveId}/images/{imgId}     { src }          images kept out of the main doc
 *    shared_notes/{liveId}/presence/{nameKey} { uid, name, color, a, f, focus, lastSeen }
 */
(function () {
    'use strict';

    const OBJ = '￼';                                   // image placeholder in stored text (same as the editor)
    const PUBLIC_NOTE_URL = 'https://gambli13.github.io/note.html';
    const OWNER_SALT = 'note-share-owner-v1';
    const OWNER_ITER = 310000;
    const OWNER_PROOF_KEY = 'noteShareOwnerProof_v1';
    const STALE_MS = 45000;                                 // presence older than this = gone (matches the rules)
    const COMMIT_DELAY = 500;                               // ms between pushes while typing
    const NAME_RE = /^[A-Za-z0-9](?:[A-Za-z0-9 _.-]{0,22}[A-Za-z0-9_.-])?$/;
    const COLORS = ['#f472b6', '#60a5fa', '#34d399', '#fbbf24', '#a78bfa', '#f87171', '#22d3ee', '#fb923c', '#a3e635', '#e879f9'];

    let F = null;   // Firestore bridge: { db, auth, doc, collection, getDoc, getDocs, setDoc, updateDoc, deleteDoc, onSnapshot, runTransaction, serverTimestamp, writeBatch, query, where, deleteField }

    const uid = () => (F && F.auth && F.auth.currentUser ? F.auth.currentUser.uid : null);
    const D = (...p) => F.doc(F.db, ...p);
    const C = (...p) => F.collection(F.db, ...p);
    const nowIso = () => new Date().toISOString();
    const isDenied = (e) => !!e && (e.code === 'permission-denied' || /insufficient permissions/i.test(e.message || ''));
    const ls = {
        get: (k) => { try { return localStorage.getItem(k); } catch (e) { return null; } },
        set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) { /* ignore */ } },
        del: (k) => { try { localStorage.removeItem(k); } catch (e) { /* ignore */ } }
    };

    // ---------- crypto-ish helpers ----------
    const te = new TextEncoder();
    const hex = (buf) => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
    const sha256 = async (str) => hex(await crypto.subtle.digest('SHA-256', te.encode(str)));
    const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const randomId = (n = 22) => {
        const out = [];
        while (out.length < n) {
            for (const b of crypto.getRandomValues(new Uint8Array(n * 2))) {
                if (b < 248 && out.length < n) out.push(ALPHA[b % 62]);   // 248 = 4*62, no modulo bias
            }
        }
        return out.join('');
    };
    const sharePwHash = (shareId, password) => sha256(`${shareId}\n${password}`);
    const deriveOwnerProof = async (passphrase) => {
        const base = await crypto.subtle.importKey('raw', te.encode(passphrase), 'PBKDF2', false, ['deriveBits']);
        const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: te.encode(OWNER_SALT), iterations: OWNER_ITER }, base, 256);
        return hex(bits);
    };
    const cyrb53 = (str, seed = 0) => {
        let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
        for (let i = 0; i < str.length; i++) {
            const ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return 4294967296 * (2097151 & h2) + (h1 >>> 0);
    };

    // ---------- images: content-addressed ids + one private-use char per image in a model ----------
    const Img = (() => {
        const srcById = new Map(), idBySrc = new Map(), charById = new Map(), idByChar = new Map();
        let next = 0xE000;
        const makeId = (src) => 'i' + cyrb53(src).toString(36) + cyrb53(src, 0x9e37).toString(36) + src.length.toString(36);
        return {
            idOf(src) {
                src = String(src || '');
                let id = idBySrc.get(src);
                if (!id) { id = makeId(src); idBySrc.set(src, id); if (!srcById.has(id)) srcById.set(id, src); }
                return id;
            },
            add(id, src) {
                if (!id || !src) return;
                if (!srcById.has(id)) srcById.set(id, src);
                if (!idBySrc.has(src)) idBySrc.set(src, id);
            },
            charOf(id) {
                let c = charById.get(id);
                if (!c) { c = String.fromCharCode(next++); charById.set(id, c); idByChar.set(c, id); }
                return c;
            },
            idOfChar: (c) => idByChar.get(c),
            src: (id) => srcById.get(id),
            has: (id) => srcById.has(id)
        };
    })();

    // ---------- model: { t: string, s: string[] } — one entry per char; images are Img chars with s = 'w<width>' ----------
    const Model = (t = '', s = []) => ({ t, s });
    const encodeRuns = (s) => {
        if (!s.some(Boolean)) return '';
        const out = [];
        let i = 0;
        while (i < s.length) {
            let j = i + 1;
            while (j < s.length && s[j] === s[i]) j++;
            out.push((j - i) + ':' + (s[i] || ''));
            i = j;
        }
        return out.join(';');
    };
    const decodeRuns = (str, len) => {
        const s = [];
        if (str) {
            for (const part of String(str).split(';')) {
                const c = part.indexOf(':');
                const n = parseInt(part.slice(0, c), 10) || 0;
                const k = part.slice(c + 1);
                for (let i = 0; i < n && s.length < len; i++) s.push(k);
            }
        }
        while (s.length < len) s.push('');
        return s;
    };
    const isPua = (ch) => { const c = ch.charCodeAt(0); return c >= 0xE000 && c <= 0xF8FF; };
    const widthOf = (key) => parseInt(String(key || '').slice(1), 10) || 0;

    const buildModel = (text, styles, ids, widths) => {
        text = String(text || '');
        const st = decodeRuns(styles || '', text.length);
        let t = '', k = 0;
        const s = [];
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (ch === OBJ) {
                const id = ids[k], w = widths[k] || 0;
                k++;
                if (!id) continue;
                t += Img.charOf(id);
                s.push('w' + w);
            } else if (isPua(ch)) {
                continue;
            } else {
                t += ch;
                s.push(st[i] || '');
            }
        }
        return Model(t, s);
    };
    const flatten = (m) => {
        let text = '';
        const ids = [], widths = [], plain = [];
        for (let i = 0; i < m.t.length; i++) {
            const ch = m.t[i];
            const id = Img.idOfChar(ch);
            if (id) { text += OBJ; ids.push(id); widths.push(widthOf(m.s[i])); plain.push(''); }
            else { text += ch; plain.push(m.s[i] || ''); }
        }
        return { text, styles: encodeRuns(plain), ids, widths };
    };
    const fromStored = (d) => buildModel(d.text, d.styles, d.imgs || [], d.imgW || []);
    const toStored = (m) => { const f = flatten(m); return { text: f.text, styles: f.styles, imgs: f.ids, imgW: f.widths }; };
    const fromIndex = (n) => buildModel(n.content, n.styles, (n.images || []).map(src => src ? Img.idOf(src) : null), n.imageSizes || []);
    const idsOf = (m) => { const out = []; for (const ch of m.t) { const id = Img.idOfChar(ch); if (id) out.push(id); } return out; };
    const eq = (a, b) => {
        if (a === b) return true;
        if (!a || !b || a.t !== b.t || a.s.length !== b.s.length) return false;
        for (let i = 0; i < a.s.length; i++) if ((a.s[i] || '') !== (b.s[i] || '')) return false;
        return true;
    };

    // ---------- diff (Myers, character level) ----------
    const MAX_D = 900;
    const myersCore = (A, B) => {
        const N = A.length, M = B.length;
        if (!N) return M ? [[1, M]] : [];
        if (!M) return [[-1, N]];
        const max = Math.min(N + M, MAX_D);
        const off = max + 1;
        const V = new Int32Array(2 * max + 3);
        const trace = [];
        for (let d = 0; d <= max; d++) {
            trace.push(V.slice());
            for (let k = -d; k <= d; k += 2) {
                let x = (k === -d || (k !== d && V[off + k - 1] < V[off + k + 1])) ? V[off + k + 1] : V[off + k - 1] + 1;
                let y = x - k;
                while (x < N && y < M && A.charCodeAt(x) === B.charCodeAt(y)) { x++; y++; }
                V[off + k] = x;
                if (x >= N && y >= M) {
                    // walk back through the saved frontiers
                    const steps = [];
                    let bx = N, by = M;
                    for (let dd = d; dd > 0; dd--) {
                        const P = trace[dd];
                        const kk = bx - by;
                        const pk = (kk === -dd || (kk !== dd && P[off + kk - 1] < P[off + kk + 1])) ? kk + 1 : kk - 1;
                        const px = P[off + pk], py = px - pk;
                        while (bx > px && by > py) { steps.push(0); bx--; by--; }
                        steps.push(bx === px ? 1 : -1);
                        bx = px; by = py;
                    }
                    while (bx > 0 && by > 0) { steps.push(0); bx--; by--; }
                    const runs = [];
                    for (let i = steps.length - 1; i >= 0; i--) {
                        const last = runs[runs.length - 1];
                        if (last && last[0] === steps[i]) last[1]++; else runs.push([steps[i], 1]);
                    }
                    return runs;
                }
            }
        }
        return [[-1, N], [1, M]];   // too different to be worth diffing finely
    };
    // [[type, len]]: 0 = same, -1 = only in a, 1 = only in b
    const diffRuns = (a, b) => {
        const n = a.length, m = b.length;
        let pre = 0;
        while (pre < n && pre < m && a.charCodeAt(pre) === b.charCodeAt(pre)) pre++;
        let suf = 0;
        while (suf < n - pre && suf < m - pre && a.charCodeAt(n - 1 - suf) === b.charCodeAt(m - 1 - suf)) suf++;
        const runs = [];
        const push = (type, len) => {
            if (!len) return;
            const last = runs[runs.length - 1];
            if (last && last[0] === type) last[1] += len; else runs.push([type, len]);
        };
        push(0, pre);
        for (const [type, len] of myersCore(a.slice(pre, n - suf), b.slice(pre, m - suf))) push(type, len);
        push(0, suf);
        return runs;
    };
    // Edits that turn base into target, in base positions
    const diffOps = (base, target) => {
        const ops = [], styles = [];
        let i = 0, j = 0, cur = null;
        const open = () => (cur = cur || { at: i, del: 0, t: '', s: [] });
        const flush = () => { if (cur) { ops.push(cur); cur = null; } };
        for (const [type, len] of diffRuns(base.t, target.t)) {
            if (type === 0) {
                flush();
                for (let q = 0; q < len; q++) {
                    const b = target.s[j + q] || '';
                    if ((base.s[i + q] || '') !== b) styles.push({ i: i + q, s: b });
                }
                i += len; j += len;
            } else if (type === -1) {
                open().del += len;
                i += len;
            } else {
                const op = open();
                op.t += target.t.slice(j, j + len);
                for (let q = 0; q < len; q++) op.s.push(target.s[j + q] || '');
                j += len;
            }
        }
        flush();
        return { ops, styles };
    };
    // Applies ops to base; map[i] = where base char i ended up (-1 = deleted),
    // insPos[i] = where text inserted "before base char i" goes (after anything already inserted there)
    const applyOps = (base, ops) => {
        const n = base.t.length;
        const t = [], s = [];
        const map = new Int32Array(n), insPos = new Int32Array(n + 1);
        let i = 0;
        const keep = () => { insPos[i] = t.length; map[i] = t.length; t.push(base.t[i]); s.push(base.s[i] || ''); i++; };
        for (const op of ops) {
            while (i < op.at) keep();
            for (let q = 0; q < op.t.length; q++) { t.push(op.t[q]); s.push(op.s[q]); }
            for (let q = 0; q < op.del; q++) { insPos[i] = t.length; map[i] = -1; i++; }
        }
        while (i < n) keep();
        insPos[n] = t.length;
        return { t, s, map, insPos };
    };
    // Three-way merge: their edits are kept as they are, mine are moved on top of them
    const merge = (base, mine, theirs) => {
        if (eq(mine, base) || eq(mine, theirs)) return theirs;
        if (eq(theirs, base)) return mine;
        const T = diffOps(base, theirs), Mi = diffOps(base, mine);
        const R = applyOps(base, T.ops);
        for (const x of T.styles) { const p = R.map[x.i]; if (p >= 0) R.s[p] = x.s; }
        const del = new Uint8Array(R.t.length);
        const ins = new Map();
        for (const op of Mi.ops) {
            for (let q = op.at; q < op.at + op.del; q++) { const p = R.map[q]; if (p >= 0) del[p] = 1; }
            if (op.t.length) {
                const p = R.insPos[op.at];
                if (!ins.has(p)) ins.set(p, []);
                ins.get(p).push(op);
            }
        }
        for (const x of Mi.styles) { const p = R.map[x.i]; if (p >= 0) R.s[p] = x.s; }
        let t = '';
        const s = [];
        const emit = (p) => { const list = ins.get(p); if (list) for (const op of list) { t += op.t; for (const k of op.s) s.push(k); } };
        for (let p = 0; p < R.t.length; p++) {
            emit(p);
            if (!del[p]) { t += R.t[p]; s.push(R.s[p]); }
        }
        emit(R.t.length);
        return Model(t, s);
    };
    // Maps a caret position in oldT to the same spot in newT (stays before text inserted right at it)
    const posMapper = (oldT, newT) => {
        if (oldT === newT) return (p) => p;
        const runs = diffRuns(oldT, newT);
        return (p) => {
            let i = 0, j = 0;
            for (const [type, len] of runs) {
                if (type === 0) { if (p < i + len) return j + (p - i); i += len; j += len; }
                else if (type === -1) { if (p < i + len) return j; i += len; }
                else { if (p === i) return j; j += len; }
            }
            return Math.max(0, Math.min(newT.length, j + (p - i)));
        };
    };

    // ---------- images in Firestore ----------
    const ensureImages = async (liveId, ids) => {
        const missing = [...new Set(ids)].filter(id => id && !Img.has(id));
        await Promise.all(missing.map(async (id) => {
            try {
                const snap = await F.getDoc(D('shared_notes', liveId, 'images', id));
                if (snap.exists()) Img.add(id, snap.data().src);
            } catch (e) { console.warn('[note-share] image', id, e); }
        }));
    };
    const uploadImages = async (liveId, model, known) => {
        for (const id of new Set(idsOf(model))) {
            if (known.has(id)) continue;
            const src = Img.src(id);
            if (!src) continue;
            try { await F.setDoc(D('shared_notes', liveId, 'images', id), { src }); }
            catch (e) { if (!isDenied(e)) throw e; }   // denied = it already exists (images are never overwritten)
            known.add(id);
        }
    };

    // ---------- live editing session (one per open shared note) ----------
    // base   = newest server version we know (model + rev)
    // shadow = the version the editor content was built on; editor minus shadow = our unsent edits
    class LiveSession {
        constructor(liveId, o) {
            this.liveId = liveId;
            this.o = o;
            this.ref = D('shared_notes', liveId);
            this.base = null;
            this.shadow = o.seed || Model();
            this.q = Promise.resolve();
            this.timer = null;
            this.retry = null;
            this.fails = 0;
            this.pendingTitle = null;
            this.title = null;
            this.latest = null;
            this.stopped = false;
            this.known = new Set();
            this.unsubs = [];
            this.state = '';
        }
        start() {
            this.unsubs.push(F.onSnapshot(this.ref, (snap) => this.onSnap(snap), (err) => this.onListenError(err)));
            this.unsubs.push(F.onSnapshot(C('shared_notes', this.liveId, 'images'), (qs) => {
                let added = false;
                qs.docChanges().forEach((ch) => {
                    if (ch.type === 'removed') return;
                    const d = ch.doc.data();
                    if (d && d.src && !Img.has(ch.doc.id)) added = true;
                    if (d && d.src) Img.add(ch.doc.id, d.src);
                    this.known.add(ch.doc.id);
                });
                if (added && this.o.onImages) this.o.onImages();
            }, () => { /* the main listener reports access problems */ }));
            return this;
        }
        stop() {
            this.stopped = true;
            clearTimeout(this.timer);
            clearTimeout(this.retry);
            this.unsubs.forEach(u => { try { u(); } catch (e) { /* ignore */ } });
            this.unsubs = [];
        }
        status(s) { if (s !== this.state) { this.state = s; if (this.o.onStatus) this.o.onStatus(s); } }
        enqueue(fn) {
            this.q = this.q.then(() => (this.stopped ? null : fn())).catch(e => console.error('[note-share]', e));
            return this.q;
        }
        schedule(delay = COMMIT_DELAY) {
            if (this.stopped || this.timer) return;
            this.timer = setTimeout(() => { this.timer = null; this.enqueue(() => this.commit()); }, delay);
        }
        localChanged() { if (!this.stopped) { this.status('dirty'); this.schedule(); } }
        setTitle(title) { this.pendingTitle = String(title || '').slice(0, 200); this.schedule(0); }
        flush() { clearTimeout(this.timer); this.timer = null; return this.enqueue(() => this.commit()); }
        hasUnsent() { return this.state === 'dirty' || this.state === 'saving' || this.state === 'error'; }

        onListenError(err) {
            console.warn('[note-share] listener', err);
            if (isDenied(err)) { this.status('denied'); if (this.o.onDenied) this.o.onDenied(err); }
            else this.status('error');
        }
        onSnap(snap) {
            if (this.stopped) return;
            if (!snap.exists()) { this.status('gone'); if (this.o.onGone) this.o.onGone(); return; }
            const d = snap.data();
            const title = d.title || '';
            if (title !== this.title) {
                this.title = title;
                if (this.pendingTitle === null && this.o.onTitle) this.o.onTitle(title);
            }
            if (this.base && d.rev <= this.base.rev) return;
            this.latest = d;
            this.enqueue(() => this.pull());
        }
        async pull() {
            const d = this.latest;
            if (!d || (this.base && d.rev <= this.base.rev)) return;
            await ensureImages(this.liveId, d.imgs || []);
            if (this.latest !== d) return;          // a newer version arrived meanwhile; its own pull handles it
            this.latest = null;
            if (this.base && d.rev <= this.base.rev) return;
            const first = !this.base;
            this.base = { m: fromStored(d), rev: d.rev };
            this.reconcile();
            if (first) { this.status(eq(this.shadow, this.base.m) ? 'saved' : this.state || 'saved'); if (this.o.onReady) this.o.onReady(d); }
            if (this.o.onRemote) this.o.onRemote(d);
        }
        // Puts the newest server version into the editor, keeping our unsent edits on top
        reconcile() {
            if (!this.base) return false;
            if (eq(this.shadow, this.base.m)) return true;
            if (this.o.busy && this.o.busy()) { this.retryLater(); return false; }
            const now = this.o.getLocal();
            const merged = merge(this.shadow, now, this.base.m);
            if (!eq(merged, now)) {
                const ok = this.o.applyRemote(merged, posMapper(now.t, merged.t));
                if (ok === false) { this.retryLater(); return false; }
            }
            this.shadow = this.base.m;
            if (!eq(merged, this.base.m)) this.schedule();
            return true;
        }
        retryLater() {
            clearTimeout(this.retry);
            this.retry = setTimeout(() => this.enqueue(() => this.reconcile()), 250);
        }
        async commit() {
            if (this.stopped) return;
            if (!this.base) { this.schedule(500); return; }
            if (this.o.busy && this.o.busy()) { this.schedule(300); return; }
            if (!this.reconcile()) return;
            const mine = this.o.getLocal();
            const title = this.pendingTitle;
            if (eq(mine, this.base.m) && title === null) { this.status('saved'); return; }
            if (this.o.readOnly) return;
            this.status('saving');
            const base = this.base;
            try {
                await uploadImages(this.liveId, mine, this.known);
                const res = await F.runTransaction(F.db, async (tx) => {
                    const snap = await tx.get(this.ref);
                    if (!snap.exists()) throw Object.assign(new Error('gone'), { code: 'not-found' });
                    const d = snap.data();
                    const result = d.rev === base.rev ? mine : merge(base.m, mine, fromStored(d));
                    const upd = { ...toStored(result), rev: d.rev + 1, updatedAt: nowIso(), updatedBy: String(this.o.who || '') };
                    if (title !== null) upd.title = title;
                    tx.update(this.ref, upd);
                    return { result, rev: d.rev + 1 };
                });
                if (title !== null && this.pendingTitle === title) { this.pendingTitle = null; this.title = title; }
                this.fails = 0;
                if (!this.base || res.rev > this.base.rev) this.base = { m: res.result, rev: res.rev };
                this.shadow = mine;
                await ensureImages(this.liveId, idsOf(this.base.m));
                this.reconcile();
                this.status(this.timer ? 'dirty' : 'saved');
            } catch (e) {
                if (isDenied(e)) { this.status('denied'); if (this.o.onDenied) this.o.onDenied(e); return; }
                if (e && e.code === 'not-found') { this.status('gone'); if (this.o.onGone) this.o.onGone(); return; }
                console.warn('[note-share] commit failed, retrying', e);
                this.status('error');
                this.fails++;
                this.schedule(Math.min(10000, 800 * this.fails));
            }
        }
    }

    // ---------- presence (names + cursors of people editing) ----------
    const presenceFresh = (p) => {
        if (!p || !p.lastSeen) return true;   // our own write that hasn't reached the server yet
        const ms = typeof p.lastSeen.toMillis === 'function' ? p.lastSeen.toMillis() : +new Date(p.lastSeen);
        return Date.now() - ms < STALE_MS;
    };
    const cleanName = (name) => String(name || '').replace(/\s+/g, ' ').trim();

    class Presence {
        constructor(liveId) {
            this.liveId = liveId;
            this.ref = null;
            this.name = null;
            this.key = null;
            this.color = null;
            this.last = { a: 0, f: 0, focus: false };
            this.pending = null;
            this.timer = null;
            this.beat = null;
            this.onLost = null;
        }
        // 'ok' | 'taken' | 'invalid' | 'denied'
        async claim(rawName) {
            const name = cleanName(rawName);
            if (!NAME_RE.test(name)) return 'invalid';
            const key = name.toLowerCase();
            const ref = D('shared_notes', this.liveId, 'presence', key);
            const used = new Set();
            try {
                const all = await F.getDocs(C('shared_notes', this.liveId, 'presence'));
                all.forEach(d => { const p = d.data(); if (p.uid !== uid() && presenceFresh(p)) used.add(p.color); });
            } catch (e) { /* colour is cosmetic */ }
            const color = (this.color && !used.has(this.color)) ? this.color : (COLORS.find(c => !used.has(c)) || COLORS[Math.floor(Math.random() * COLORS.length)]);
            let takenBySomeone = false;
            try {
                await F.runTransaction(F.db, async (tx) => {
                    const cur = await tx.get(ref);
                    if (cur.exists()) {
                        const p = cur.data();
                        if (p.uid !== uid() && presenceFresh(p)) { takenBySomeone = true; throw new Error('taken'); }
                    }
                    tx.set(ref, { uid: uid(), name, color, a: 0, f: 0, focus: false, lastSeen: F.serverTimestamp() });
                });
            } catch (e) {
                if (takenBySomeone) return 'taken';
                if (isDenied(e)) return 'taken';   // the rules saw it as still in use
                throw e;
            }
            if (this.ref && this.key !== key) this.leave();
            this.ref = ref; this.name = name; this.key = key; this.color = color;
            clearInterval(this.beat);
            this.beat = setInterval(() => this.heartbeat(), 15000);
            return 'ok';
        }
        setSel(a, f, focus) {
            if (!this.ref) return;
            const p = { a: a | 0, f: f | 0, focus: !!focus };
            if (p.a === this.last.a && p.f === this.last.f && p.focus === this.last.focus && !this.pending) return;
            this.pending = p;
            if (!this.timer) this.timer = setTimeout(() => this.push(), 300);
        }
        heartbeat() { if (this.ref) { this.pending = this.pending || { ...this.last }; this.push(); } }
        async push() {
            clearTimeout(this.timer);
            this.timer = null;
            if (!this.ref || !this.pending) return;
            const p = this.pending;
            this.pending = null;
            this.last = p;
            try {
                await F.updateDoc(this.ref, { a: p.a, f: p.f, focus: p.focus, lastSeen: F.serverTimestamp() });
            } catch (e) {
                if (isDenied(e) || (e && e.code === 'not-found')) {
                    // We went quiet long enough for someone else to take the name (or it was cleaned up)
                    const name = this.name;
                    this.ref = null;
                    clearInterval(this.beat);
                    const r = await this.claim(name).catch(() => 'denied');
                    if (r !== 'ok' && this.onLost) this.onLost(r);
                }
            }
        }
        leave() {
            clearTimeout(this.timer);
            clearInterval(this.beat);
            const ref = this.ref;
            this.ref = null;
            if (ref) F.deleteDoc(ref).catch(() => { /* goes stale on its own */ });
        }
    }
    const watchPresence = (liveId, cb) => {
        let last = [];
        const emit = () => cb(last.filter(presenceFresh));
        const unsub = F.onSnapshot(C('shared_notes', liveId, 'presence'), (qs) => {
            last = qs.docs.map(d => ({ key: d.id, ...d.data({ serverTimestamps: 'estimate' }) }));
            emit();
        }, (e) => console.warn('[note-share] presence', e));
        const tick = setInterval(emit, 10000);
        return () => { unsub(); clearInterval(tick); };
    };

    // ---------- owner: passphrase that proves "this device is Matt's" ----------
    let ownerReadyUid = null;
    const registerOwner = (proof) => F.setDoc(D('note_share_owners', uid()), { proof, at: F.serverTimestamp() });
    const owner = {
        // 'ready' | 'setup' | 'unlock' | 'norules' | 'offline'
        async state() {
            if (!F || !uid()) return 'offline';
            if (ownerReadyUid === uid()) return 'ready';
            // The new rules make this doc unreadable; if we CAN read it, the rules weren't deployed.
            try { await F.getDoc(D('note_share_cfg', 'owner')); return 'norules'; }
            catch (e) { if (!isDenied(e)) throw e; }
            const stored = ls.get(OWNER_PROOF_KEY);
            if (stored) {
                try { await registerOwner(stored); ownerReadyUid = uid(); return 'ready'; }
                catch (e) { if (isDenied(e)) ls.del(OWNER_PROOF_KEY); else throw e; }
            }
            const marker = await F.getDoc(D('note_share_cfg', 'marker'));
            return marker.exists() ? 'unlock' : 'setup';
        },
        async setup(passphrase) {
            const proof = await deriveOwnerProof(passphrase);
            const batch = F.writeBatch(F.db);
            batch.set(D('note_share_cfg', 'owner'), { proof });
            batch.set(D('note_share_cfg', 'marker'), { setupAt: F.serverTimestamp() });
            try { await batch.commit(); }
            catch (e) { if (isDenied(e)) throw Object.assign(new Error('A sharing passphrase already exists'), { code: 'exists' }); throw e; }
            await registerOwner(proof);
            ls.set(OWNER_PROOF_KEY, proof);
            ownerReadyUid = uid();
        },
        async unlock(passphrase) {
            const proof = await deriveOwnerProof(passphrase);
            try { await registerOwner(proof); }
            catch (e) { if (isDenied(e)) throw Object.assign(new Error('Wrong passphrase'), { code: 'wrong' }); throw e; }
            ls.set(OWNER_PROOF_KEY, proof);
            ownerReadyUid = uid();
        },
        forget() { ls.del(OWNER_PROOF_KEY); ownerReadyUid = null; }
    };

    // ---------- owner: links ----------
    const admin = {
        linkFor(shareId) {
            let base = PUBLIC_NOTE_URL;
            try { if (/^https?:$/.test(location.protocol)) base = new URL('note.html', location.href).href; } catch (e) { /* keep the public URL */ }
            return `${base}?id=${encodeURIComponent(shareId)}`;
        },
        async createLive(title, model) {
            const liveId = randomId(20);
            await uploadImages(liveId, model, new Set());
            await F.setDoc(D('shared_notes', liveId), { ...toStored(model), title: String(title || 'Note').slice(0, 200), rev: 1, updatedAt: nowIso(), updatedBy: 'Owner' });
            return liveId;
        },
        async getLive(liveId) {
            const snap = await F.getDoc(D('shared_notes', liveId));
            return snap.exists() ? snap.data() : null;
        },
        watchLive(liveId, cb, onErr) {
            return F.onSnapshot(D('shared_notes', liveId), (snap) => cb(snap.exists() ? snap.data() : null), (e) => { if (onErr) onErr(e); });
        },
        async fetchImages(liveId, ids) {
            await ensureImages(liveId, ids);
            return ids.map(id => Img.src(id) || null);
        },
        async setLiveTitle(liveId, title) {
            const ref = D('shared_notes', liveId);
            await F.runTransaction(F.db, async (tx) => {
                const snap = await tx.get(ref);
                if (!snap.exists()) return;
                const d = snap.data();
                if ((d.title || '') === title) return;
                tx.update(ref, { title: String(title || '').slice(0, 200), rev: d.rev + 1, updatedAt: nowIso(), updatedBy: 'Owner' });
            });
        },
        async listShares(liveId) {
            const qs = await F.getDocs(F.query(C('note_shares'), F.where('liveId', '==', liveId)));
            return qs.docs.map(d => ({ id: d.id, ...d.data() }));
        },
        async createShare(liveId, mode, password) {
            if (mode !== 'view' && mode !== 'edit') throw new Error('bad mode');
            const id = randomId(22);
            const batch = F.writeBatch(F.db);
            batch.set(D('note_shares', id), { liveId, mode, hasPassword: !!password, createdAt: nowIso() });
            if (password) batch.set(D('note_shares', id, 'secret', 'pw'), { hash: await sharePwHash(id, password) });
            await batch.commit();
            return id;
        },
        async setSharePassword(shareId, password) {
            const batch = F.writeBatch(F.db);
            if (password) batch.set(D('note_shares', shareId, 'secret', 'pw'), { hash: await sharePwHash(shareId, password) });
            else batch.delete(D('note_shares', shareId, 'secret', 'pw'));
            batch.update(D('note_shares', shareId), { hasPassword: !!password });
            await batch.commit();
        },
        async deleteShare(shareId) {
            const batch = F.writeBatch(F.db);
            batch.delete(D('note_shares', shareId, 'secret', 'pw'));
            batch.delete(D('note_shares', shareId));
            await batch.commit();
        },
        // Turns every link off, then removes the live copy (the note itself stays in the dashboard)
        async destroyLive(liveId) {
            for (const s of await admin.listShares(liveId)) await admin.deleteShare(s.id);
            for (const sub of ['presence', 'members', 'images']) {
                const qs = await F.getDocs(C('shared_notes', liveId, sub));
                let batch = F.writeBatch(F.db), n = 0;
                for (const d of qs.docs) {
                    batch.delete(d.ref);
                    if (++n === 400) { await batch.commit(); batch = F.writeBatch(F.db); n = 0; }
                }
                if (n) await batch.commit();
            }
            await F.deleteDoc(D('shared_notes', liveId));
        }
    };

    // ---------- link holders ----------
    const join = {
        async loadShare(shareId) {
            const snap = await F.getDoc(D('note_shares', shareId));
            return snap.exists() ? { id: shareId, ...snap.data() } : null;
        },
        watchShare(shareId, onGone) {
            return F.onSnapshot(D('note_shares', shareId), (snap) => { if (!snap.exists()) onGone(); }, () => { /* ignore */ });
        },
        // true when this browser already got in through this link (and still may)
        async checkMember(share) {
            try {
                const m = await F.getDoc(D('shared_notes', share.liveId, 'members', uid()));
                if (!m.exists() || m.data().shareId !== share.id || m.data().role !== share.mode) return false;
                await F.getDoc(D('shared_notes', share.liveId));
                return true;
            } catch (e) { return false; }
        },
        // The rules check the password; a wrong one is refused by Firestore itself
        async enter(share, password) {
            const proof = share.hasPassword ? await sharePwHash(share.id, String(password || '')) : '';
            try {
                await F.setDoc(D('shared_notes', share.liveId, 'members', uid()), { shareId: share.id, role: share.mode, proof, at: F.serverTimestamp() });
            } catch (e) {
                if (isDenied(e)) throw Object.assign(new Error(share.hasPassword ? 'Wrong password' : 'Access denied'), { code: share.hasPassword ? 'wrong-password' : 'denied' });
                throw e;
            }
        }
    };

    window.NoteShare = {
        init(bridge) { F = bridge; },
        ready: () => !!(F && uid()),
        uid,
        deleteField: () => F.deleteField(),
        OBJ, COLORS, NAME_RE, Img,
        model: { fromStored, toStored, fromIndex, idsOf, eq, merge, posMapper, diffRuns, Model },
        LiveSession, Presence, watchPresence, cleanName,
        owner, admin, join
    };
})();
