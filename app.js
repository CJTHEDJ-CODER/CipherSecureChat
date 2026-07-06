// =============================================================
// Cipher — local-first, end-to-end encrypted 1:1 chat
// =============================================================
// Security model:
//  - Each device generates its own long-term ECDH (P-256) identity
//    keypair on first run. Private key stored non-extractable in
//    IndexedDB -- usable by this browser, never exportable again.
//  - Adding a friend = share a short invite code through ANY channel
//    (text, email, in person) -- it only contains a public key, which
//    isn't secret. After pairing, a "safety number" is shown; read it
//    aloud to each other (call/video) to confirm nobody tampered with
//    the code in transit.
//  - Every chat SESSION (each time you open a chat / reconnect) does
//    a fresh Diffie-Hellman handshake using new ephemeral keys before
//    any message can be sent. This means even if one session's keys
//    were ever compromised, past and future sessions stay secure
//    (post-compromise security / healing).
//  - Within a session, every single message is encrypted with its own
//    key, pulled from a one-way ratcheting chain -- so recovering one
//    message's key never reveals any other message's key (forward
//    secrecy).
//  - The relay server only ever forwards already-encrypted bytes
//    between a room ID derived from both public keys. It cannot read
//    messages, and never logs or stores anything to disk.
//  - Message history is OFF by default. If enabled in Settings, it's
//    kept only in this browser's local storage -- never uploaded.
//
// Honest limits: this protects message CONTENT very seriously. It does
// not hide metadata (that you and a contact talk, when, how often) from
// whoever operates your relay server, and it's a from-scratch build,
// not an independently audited one like Signal's -- treat it as strong
// hobbyist-grade security, not a guarantee against nation-state actors.

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------------------------------------------------------------
// IndexedDB
// ---------------------------------------------------------------
const DB_NAME = 'cipher-db';
const DB_VERSION = 1;

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('identity')) db.createObjectStore('identity', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('contacts')) db.createObjectStore('contacts', { keyPath: 'id' });
      if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings', { keyPath: 'key' });
      if (!db.objectStoreNames.contains('messages')) {
        const s = db.createObjectStore('messages', { keyPath: 'msgId', autoIncrement: true });
        s.createIndex('byContact', 'contactId');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}
async function idbGet(store, key) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error);
  });
}
async function idbPut(store, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readwrite');
    tx.objectStore(store).put(value);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}
async function idbGetAll(store) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}
async function idbGetByIndex(store, indexName, value) {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(store, 'readonly');
    const req = tx.objectStore(store).index(indexName).getAll(value);
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error);
  });
}
async function idbClearAll() {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(['identity', 'contacts', 'settings', 'messages'], 'readwrite');
    tx.objectStore('identity').clear();
    tx.objectStore('contacts').clear();
    tx.objectStore('settings').clear();
    tx.objectStore('messages').clear();
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

// ---------------------------------------------------------------
// base64 helpers
// ---------------------------------------------------------------
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64ToBuf(b64) {
  const norm = b64.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm.length % 4 === 0 ? '' : '='.repeat(4 - (norm.length % 4));
  const bin = atob(norm + pad);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function concatBufs(...parts) {
  const total = parts.reduce((n, p) => n + p.byteLength, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(new Uint8Array(p), off); off += p.byteLength; }
  return out.buffer;
}

// ---------------------------------------------------------------
// Identity (long-term ECDH keypair, one per device)
// ---------------------------------------------------------------
let myIdentity = null; // { privateKey: CryptoKey (non-extractable), publicKeyRaw: base64 }

async function ensureIdentity() {
  const existing = await idbGet('identity', 'me');
  if (existing) { myIdentity = existing; return; }
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const pubRaw = await crypto.subtle.exportKey('raw', pair.publicKey);
  const privPkcs8 = await crypto.subtle.exportKey('pkcs8', pair.privateKey);
  const nonExtractablePriv = await crypto.subtle.importKey(
    'pkcs8', privPkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );
  myIdentity = { id: 'me', privateKey: nonExtractablePriv, publicKeyRaw: bufToB64(pubRaw) };
  await idbPut('identity', myIdentity);
}

async function importRawPublicKey(rawB64) {
  return crypto.subtle.importKey('raw', b64ToBuf(rawB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
}

async function hkdfBytes(ikmBytes, infoStr, length = 32) {
  const key = await crypto.subtle.importKey('raw', ikmBytes, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode(infoStr) },
    key, length * 8
  );
  return new Uint8Array(bits);
}

async function aesKeyFromBytes(keyBytes) {
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function roomIdFor(pubA, pubB) {
  const sorted = [pubA, pubB].sort().join('|');
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(sorted));
  return bufToB64(digest).replace(/[^a-zA-Z0-9]/g, '').slice(0, 32);
}

async function safetyNumberFor(longtermSharedBits) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', longtermSharedBits));
  const groups = [];
  for (let i = 0; i < 8; i += 2) {
    const n = ((digest[i] << 8) | digest[i + 1]) % 10000;
    groups.push(String(n).padStart(4, '0'));
  }
  return groups.join('  ');
}

// ---------------------------------------------------------------
// Ratchet: per-session handshake + per-message forward-secret chain
// ---------------------------------------------------------------
// One RatchetSession object lives for as long as a chat screen is open.
// Opening the chat again later (even with the same contact) makes a
// brand new one with fresh ephemeral keys -- that's what gives us
// healing between sessions.
class RatchetSession {
  constructor(contact) {
    this.contact = contact;
    this.myRole = myIdentity.publicKeyRaw < contact.publicKeyRaw ? 'A' : 'B';
    this.otherRole = this.myRole === 'A' ? 'B' : 'A';
    this.ready = false;
    this.myEphPriv = null;
    this.myEphPubRaw = null;
    this.chainOut = null;
    this.chainIn = null;
    this._helloSent = false;
    this._helloReceivedFrom = null;
  }

  async init() {
    const peerLongtermPub = await importRawPublicKey(this.contact.publicKeyRaw);
    this.longtermSharedBits = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerLongtermPub }, myIdentity.privateKey, 256
    );
    const ephPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    this.myEphPubRaw = bufToB64(await crypto.subtle.exportKey('raw', ephPair.publicKey));
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', ephPair.privateKey);
    this.myEphPriv = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
  }

  // called once we've both exchanged HELLO(ephemeral pubkey)
  async finishHandshake(theirEphPubRawB64) {
    const theirEphPub = await importRawPublicKey(theirEphPubRawB64);
    const dhOut = await crypto.subtle.deriveBits({ name: 'ECDH', public: theirEphPub }, this.myEphPriv, 256);
    const sessionRoot = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', concatBufs(this.longtermSharedBits, dhOut, enc.encode('cipher-session-root'))
    ));
    this.chainOut = await hkdfBytes(sessionRoot, 'chain-' + this.myRole);
    this.chainIn = await hkdfBytes(sessionRoot, 'chain-' + this.otherRole);
    this.ready = true;
  }

  async nextSendKey() {
    const msgKeyBytes = await hkdfBytes(this.chainOut, 'msg');
    this.chainOut = await hkdfBytes(this.chainOut, 'step');
    return aesKeyFromBytes(msgKeyBytes);
  }

  async nextRecvKey() {
    const msgKeyBytes = await hkdfBytes(this.chainIn, 'msg');
    this.chainIn = await hkdfBytes(this.chainIn, 'step');
    return aesKeyFromBytes(msgKeyBytes);
  }
}

async function encryptWithKey(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(plaintext));
  const blob = new Uint8Array(iv.length + ct.byteLength);
  blob.set(iv, 0);
  blob.set(new Uint8Array(ct), iv.length);
  return bufToB64(blob.buffer);
}
async function decryptWithKey(aesKey, token) {
  const blob = new Uint8Array(b64ToBuf(token));
  const iv = blob.slice(0, 12);
  const ct = blob.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
  return dec.decode(pt);
}

// ---------------------------------------------------------------
// Settings
// ---------------------------------------------------------------
async function getSetting(key, fallback) {
  const rec = await idbGet('settings', key);
  return rec ? rec.value : fallback;
}
async function setSetting(key, value) { await idbPut('settings', { key, value }); }

// ---------------------------------------------------------------
// UI navigation
// ---------------------------------------------------------------
function show(screenId) {
  document.querySelectorAll('.screen').forEach(el => el.classList.add('hidden'));
  document.getElementById(screenId).classList.remove('hidden');
}
document.querySelectorAll('[data-back]').forEach(btn => {
  btn.addEventListener('click', () => {
    disconnectChat();
    show(btn.dataset.back);
    renderContacts();
  });
});
function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ---------------------------------------------------------------
// Contacts list
// ---------------------------------------------------------------
async function renderContacts() {
  const list = document.getElementById('contact-list');
  const contacts = await idbGetAll('contacts');
  list.innerHTML = '';
  if (contacts.length === 0) {
    list.innerHTML = `<div class="empty-state">
      <div class="glyph">◎</div>
      <h3>No contacts yet</h3>
      <p>Tap the + button, share your invite code with a friend (text, email, however), and paste theirs back.</p>
    </div>`;
    return;
  }
  contacts.forEach(c => {
    const row = document.createElement('div');
    row.className = 'contact-row';
    row.innerHTML = `<div class="avatar">${(c.nickname || '?').slice(0,1).toUpperCase()}</div>
      <div><div class="contact-name">${escapeHtml(c.nickname)}</div>
      <div class="contact-meta">${c.roomId.slice(0,12)}…</div></div>`;
    row.addEventListener('click', () => openChat(c));
    list.appendChild(row);
  });
}

// ---------------------------------------------------------------
// Add friend: invite code flow (no camera, works across the world)
// ---------------------------------------------------------------
const INVITE_PREFIX = 'CIPHER1-';

function buildInviteCode() {
  const payload = JSON.stringify({ t: 'cipher-invite', k: myIdentity.publicKeyRaw });
  return INVITE_PREFIX + bufToB64(enc.encode(payload).buffer);
}

function parseInviteCode(raw) {
  const trimmed = raw.trim();
  if (!trimmed.startsWith(INVITE_PREFIX)) return null;
  try {
    const json = dec.decode(b64ToBuf(trimmed.slice(INVITE_PREFIX.length)));
    const payload = JSON.parse(json);
    if (payload.t !== 'cipher-invite' || !payload.k) return null;
    return payload.k;
  } catch { return null; }
}

document.getElementById('btn-add-friend').addEventListener('click', () => {
  const code = buildInviteCode();
  document.getElementById('my-invite-code').value = code;
  show('screen-my-code');
});

document.getElementById('btn-copy-code').addEventListener('click', async () => {
  const code = document.getElementById('my-invite-code').value;
  try {
    await navigator.clipboard.writeText(code);
    flashButton('btn-copy-code', 'Copied ✓');
  } catch {
    document.getElementById('my-invite-code').select();
  }
});

document.getElementById('btn-share-code').addEventListener('click', async () => {
  const code = document.getElementById('my-invite-code').value;
  if (navigator.share) {
    try { await navigator.share({ title: 'My Cipher invite code', text: code }); } catch {}
  } else {
    await navigator.clipboard.writeText(code).catch(() => {});
    flashButton('btn-share-code', 'Copied ✓');
  }
});

function flashButton(id, text) {
  const btn = document.getElementById(id);
  const original = btn.textContent;
  btn.textContent = text;
  setTimeout(() => { btn.textContent = original; }, 1200);
}

document.getElementById('btn-goto-paste').addEventListener('click', () => {
  document.getElementById('paste-code-input').value = '';
  document.getElementById('paste-status').textContent = '';
  show('screen-add-code');
});

let pendingPeer = null; // { publicKeyRaw, roomId, safetyNumber }

document.getElementById('btn-parse-code').addEventListener('click', async () => {
  const raw = document.getElementById('paste-code-input').value;
  const peerPubB64 = parseInviteCode(raw);
  const statusEl = document.getElementById('paste-status');
  if (!peerPubB64) {
    statusEl.textContent = "That doesn't look like a valid Cipher invite code.";
    return;
  }
  if (peerPubB64 === myIdentity.publicKeyRaw) {
    statusEl.textContent = "That's your own code — ask your friend for theirs.";
    return;
  }
  statusEl.textContent = 'Verifying…';
  const peerPublicKey = await importRawPublicKey(peerPubB64);
  const sharedBits = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, myIdentity.privateKey, 256);
  const roomId = await roomIdFor(myIdentity.publicKeyRaw, peerPubB64);
  const safetyNumber = await safetyNumberFor(sharedBits);
  pendingPeer = { publicKeyRaw: peerPubB64, roomId, safetyNumber };
  document.getElementById('fingerprint-display').textContent = safetyNumber;
  document.getElementById('nickname-input').value = '';
  show('screen-confirm');
});

document.getElementById('btn-save-contact').addEventListener('click', async () => {
  const nickname = document.getElementById('nickname-input').value.trim() || 'Friend';
  const contact = {
    id: pendingPeer.roomId,
    nickname,
    publicKeyRaw: pendingPeer.publicKeyRaw,
    roomId: pendingPeer.roomId,
    safetyNumber: pendingPeer.safetyNumber,
    createdAt: Date.now(),
  };
  await idbPut('contacts', contact);
  pendingPeer = null;
  show('screen-contacts');
  renderContacts();
});

// ---------------------------------------------------------------
// Chat
// ---------------------------------------------------------------
let activeContact = null;
let activeSocket = null;
let activeSession = null;
let keepHistory = false;

async function openChat(contact) {
  activeContact = contact;
  document.getElementById('chat-name').textContent = contact.nickname;
  document.getElementById('chat-avatar').textContent = contact.nickname.slice(0, 1).toUpperCase();
  document.getElementById('messages').innerHTML = '';
  document.getElementById('msg-input').disabled = true;
  setChatStatus('connecting');
  show('screen-chat');

  activeSession = new RatchetSession(contact);
  await activeSession.init();

  keepHistory = await getSetting('keepHistory', false);
  if (keepHistory) {
    const history = await idbGetByIndex('messages', 'byContact', contact.id);
    history.sort((a, b) => a.ts - b.ts);
    history.forEach(m => addBubble(m.mine ? 'mine' : 'theirs', m.text));
  }

  connectChat(contact.roomId);
}

async function connectChat(roomId) {
  const relayUrl = await getSetting('relayUrl', '');
  if (!relayUrl) {
    addBubble('system', 'No relay server set. Add one in Settings first.');
    setChatStatus('');
    return;
  }
  try {
    activeSocket = new WebSocket(relayUrl);
  } catch (e) {
    addBubble('system', 'Could not connect: ' + e.message);
    return;
  }
  activeSocket.onopen = () => {
    activeSocket.send('JOIN:' + roomId);
  };
  activeSocket.onmessage = async (ev) => {
    const data = ev.data;
    if (data.startsWith('ROLE:')) {
      // send our handshake HELLO now that we're in the room
      activeSocket.send('HELLO:' + activeSession.myEphPubRaw);
      addBubble('system', 'Establishing a fresh secure session…');
      return;
    }
    if (data.startsWith('PEERJOINED:')) {
      // our peer just connected -- our earlier HELLO (if any) may have
      // been sent before they joined and gone nowhere. Resend it now.
      activeSocket.send('HELLO:' + activeSession.myEphPubRaw);
      return;
    }
    if (data.startsWith('HELLO:')) {
      const theirEph = data.slice('HELLO:'.length);
      await activeSession.finishHandshake(theirEph);
      setChatStatus('connected');
      document.getElementById('msg-input').disabled = false;
      addBubble('system', 'Secure session established — every message uses its own key.');
      return;
    }
    if (data.startsWith('MSG:')) {
      if (!activeSession.ready) return; // shouldn't happen, but never decrypt before handshake
      const token = data.slice(4);
      try {
        const key = await activeSession.nextRecvKey();
        const plaintext = await decryptWithKey(key, token);
        addBubble('theirs', plaintext);
        if (keepHistory) {
          await idbPut('messages', { contactId: activeContact.id, mine: false, text: plaintext, ts: Date.now() });
        }
      } catch (e) {
        addBubble('system', 'Received a message that failed to decrypt (out of sync or tampered).');
      }
    }
  };
  activeSocket.onclose = () => { setChatStatus(''); document.getElementById('msg-input').disabled = true; };
  activeSocket.onerror = () => { setChatStatus(''); };
}

function disconnectChat() {
  if (activeSocket) { try { activeSocket.close(); } catch {} activeSocket = null; }
  activeContact = null;
  activeSession = null;
}

function setChatStatus(state) {
  const dot = document.getElementById('chat-dot');
  const label = document.getElementById('chat-status');
  dot.className = 'status-dot' + (state ? ' ' + state : '');
  label.lastChild && (label.lastChild.textContent = ' ' + (state || 'offline'));
}

function addBubble(kind, text) {
  const wrap = document.getElementById('messages');
  const el = document.createElement('div');
  el.className = 'msg ' + kind;
  el.textContent = text;
  wrap.appendChild(el);
  wrap.scrollTop = wrap.scrollHeight;
}

document.getElementById('btn-send').addEventListener('click', sendCurrentMessage);
document.getElementById('msg-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendCurrentMessage();
});

async function sendCurrentMessage() {
  const input = document.getElementById('msg-input');
  const text = input.value.trim();
  if (!text || !activeSocket || activeSocket.readyState !== WebSocket.OPEN) return;
  if (!activeSession || !activeSession.ready) return;
  const key = await activeSession.nextSendKey();
  const token = await encryptWithKey(key, text);
  activeSocket.send('MSG:' + token);
  addBubble('mine', text);
  if (keepHistory) {
    await idbPut('messages', { contactId: activeContact.id, mine: true, text, ts: Date.now() });
  }
  input.value = '';
}

// ---------------------------------------------------------------
// Settings screen
// ---------------------------------------------------------------
document.getElementById('btn-open-settings').addEventListener('click', async () => {
  document.getElementById('relay-input').value = await getSetting('relayUrl', '');
  document.getElementById('toggle-history').checked = await getSetting('keepHistory', false);
  document.getElementById('my-pubkey-display').textContent = myIdentity.publicKeyRaw;
  show('screen-settings');
});
document.getElementById('btn-save-relay').addEventListener('click', async () => {
  const val = document.getElementById('relay-input').value.trim();
  await setSetting('relayUrl', val);
  flashButton('btn-save-relay', 'Saved ✓');
});
document.getElementById('toggle-history').addEventListener('change', async (e) => {
  await setSetting('keepHistory', e.target.checked);
});
document.getElementById('btn-wipe').addEventListener('click', async () => {
  if (!confirm('This deletes your identity, contacts, settings, and any local history on THIS device. Your friends will need to re-pair with you afterward. This cannot be undone. Continue?')) return;
  await idbClearAll();
  location.reload();
});

// ---------------------------------------------------------------
// Boot
// ---------------------------------------------------------------
(async function boot() {
  await ensureIdentity();
  await renderContacts();
  show('screen-contacts');
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
})();
