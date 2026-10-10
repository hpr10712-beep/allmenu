const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const crypto = require("crypto");
admin.initializeApp();
const db = admin.database();
const REGION = "asia-southeast2";

const requireAuth = req => { if(!req.auth) throw new HttpsError("unauthenticated","Login diperlukan"); };

async function generateUniqueAccountId() {
  for (let i = 0; i < 15; i++) {
    const len = 8 + Math.floor(Math.random() * 3); // 8..10
    let id = "";
    for (let k = 0; k < len; k++) id += Math.floor(Math.random() * 10);
    if (id[0] === "0") id = "1" + id.slice(1);
    const ref = db.ref(`accountIds/${id}`);
    const res = await ref.transaction(cur => cur === null ? "PENDING" : undefined);
    if (res.committed) return id;
  }
  throw new HttpsError("internal","Gagal generate ID");
}

async function ensureWallet(uid) {
  const r = db.ref(`wallets/${uid}`);
  if (!(await r.get()).exists()) {
    await r.set({ userId: uid, availableBalance: 0, pendingBalance: 0, currency: "IDR", updatedAt: Date.now() });
  }
}

const sha256 = str => crypto.createHash("sha256").update(str).digest("hex");

async function checkPin(uid, pin) {
  if (!/^\d{6}$/.test(pin)) throw new HttpsError("invalid-argument","PIN tidak valid");
  const ref = db.ref(`users/${uid}`);
  const snap = await ref.get();
  if (!snap.exists()) throw new HttpsError("not-found","User tidak ditemukan");
  const u = snap.val();
  const now = Date.now();
  const att = u.pinAttempts || { count: 0, until: 0 };
  if (att.until && now < att.until) {
    const mins = Math.ceil((att.until - now) / 60000);
    throw new HttpsError("resource-exhausted", `PIN terkunci. Coba lagi dalam ${mins} menit.`);
  }
  const expected = sha256((u.pinSalt || "") + ":" + pin);
  if (expected !== u.pinHash) {
    const count = (att.count || 0) + 1;
    const until = count >= 5 ? now + 15 * 60 * 1000 : 0;
    await ref.update({ pinAttempts: { count: count >= 5 ? 0 : count, until } });
    throw new HttpsError("permission-denied","PIN salah.");
  }
  if (att.count || att.until) await ref.update({ pinAttempts: { count: 0, until: 0 } });
}

/* ====== FINALIZE REGISTRATION ====== */
exports.finalizeRegistration = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const uid = req.auth.uid;
  const { displayName, pinHash, pinSalt } = req.data || {};
  if (!displayName || !pinHash || !pinSalt) throw new HttpsError("invalid-argument","Data tidak lengkap");
  if (displayName.length > 40) throw new HttpsError("invalid-argument","Nama terlalu panjang");
  if (!/^[a-f0-9]{64}$/.test(pinHash) || !/^[a-f0-9]{32}$/.test(pinSalt))
    throw new HttpsError("invalid-argument","Hash tidak valid");

  const userRef = db.ref(`users/${uid}`);
  const ex = await userRef.get();
  if (ex.exists() && ex.val().accountId) return { accountId: ex.val().accountId, alreadyExists: true };

  const accountId = await generateUniqueAccountId();
  const now = Date.now();
  await db.ref().update({
    [`users/${uid}`]: {
      accountId, displayName,
      email: req.auth.token.email || "",
      accountStatus: "active", pinHash, pinSalt,
      pinAttempts: { count: 0, until: 0 },
      createdAt: now
    },
    [`wallets/${uid}`]: {
      userId: uid, availableBalance: 0, pendingBalance: 0, currency: "IDR", updatedAt: now
    },
    [`accountIds/${accountId}`]: uid
  });
  return { accountId };
});

/* ====== VERIFY PIN ====== */
exports.verifyPin = onCall({ region: REGION }, async req => {
  requireAuth(req);
  await checkPin(req.auth.uid, req.data?.pin);
  return { ok: true };
});

/* ====== CHANGE PIN ====== */
exports.changePin = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const { oldPin, newPinHash, newPinSalt } = req.data || {};
  await checkPin(req.auth.uid, oldPin);
  if (!/^[a-f0-9]{64}$/.test(newPinHash) || !/^[a-f0-9]{32}$/.test(newPinSalt))
    throw new HttpsError("invalid-argument","Hash tidak valid");
  await db.ref(`users/${req.auth.uid}`).update({ pinHash: newPinHash, pinSalt: newPinSalt });
  return { ok: true };
});

/* ====== TRANSFER ====== */
exports.transfer = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const { receiverUid, amount, note, idempotencyKey } = req.data || {};
  const senderUid = req.auth.uid;
  if (!receiverUid || receiverUid === senderUid) throw new HttpsError("invalid-argument","Penerima tidak valid");
  if (!Number.isInteger(amount) || amount < 1000 || amount > 10_000_000)
    throw new HttpsError("invalid-argument","Nominal tidak valid");
  if (!idempotencyKey || typeof idempotencyKey !== "string" || idempotencyKey.length > 80)
    throw new HttpsError("invalid-argument","idempotencyKey wajib");

  const idemRef = db.ref(`idempotency/${senderUid}/${idempotencyKey}`);
  const ex = await idemRef.get();
  if (ex.exists()) return ex.val();

  const [sProf, rProf] = await Promise.all([
    db.ref(`users/${senderUid}`).get(),
    db.ref(`users/${receiverUid}`).get()
  ]);
  if (!sProf.exists() || !rProf.exists()) throw new HttpsError("not-found","Akun tidak ditemukan");
  if (sProf.val().accountStatus !== "active") throw new HttpsError("permission-denied","Akun Anda tidak aktif");
  if (rProf.val().accountStatus !== "active") throw new HttpsError("failed-precondition","Akun penerima tidak aktif");

  await Promise.all([ensureWallet(senderUid), ensureWallet(receiverUid)]);

  const refNum = "TRX" + crypto.randomBytes(5).toString("hex").toUpperCase();
  const now = Date.now();

  const result = await db.ref().transaction(async txn => {
    const sS = await txn.get(db.ref(`wallets/${senderUid}`));
    const rS = await txn.get(db.ref(`wallets/${receiverUid}`));
    const sBal = sS.val()?.availableBalance || 0;
    if (sBal < amount) throw new HttpsError("failed-precondition","Saldo tidak cukup");

    const outId = db.ref("transactions").push().key;
    const inId  = db.ref("transactions").push().key;

    txn.set(db.ref(`transactions/${outId}`), {
      userId: senderUid, senderId: senderUid, receiverId: receiverUid,
      transactionType: "TRANSFER_OUT", amount, fee: 0, status: "success",
      createdAt: now, updatedAt: now, referenceNumber: refNum,
      description: (note || "Transfer").slice(0, 60),
      idempotencyKey
    });
    txn.set(db.ref(`transactions/${inId}`), {
      userId: receiverUid, senderId: senderUid, receiverId: receiverUid,
      transactionType: "TRANSFER_IN", amount, fee: 0, status: "success",
      createdAt: now, updatedAt: now, referenceNumber: refNum,
      description: (note || "Transfer").slice(0, 60),
      idempotencyKey
    });
    txn.update(db.ref(`wallets/${senderUid}`), { availableBalance: sBal - amount, updatedAt: now });
    txn.update(db.ref(`wallets/${receiverUid}`), {
      availableBalance: (rS.val()?.availableBalance || 0) + amount, updatedAt: now
    });
    txn.set(db.ref(`notifications/${senderUid}`).push(), {
      title: "Transfer berhasil",
      message: `${amount} ke ${rProf.val().displayName || receiverUid}`,
      type: "transfer_out", read: false, createdAt: now, link: "activity"
    });
    txn.set(db.ref(`notifications/${receiverUid}`).push(), {
      title: "Transfer masuk",
      message: `${amount} dari ${sProf.val().displayName || senderUid}`,
      type: "transfer_in", read: false, createdAt: now, link: "activity"
    });
    return { transactionId: outId, referenceNumber: refNum };
  });

  await idemRef.set(result);
  return result;
});

/* ====== TOPUP REQUEST (stub) ====== */
exports.createTopupRequest = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const { amount, method, idempotencyKey } = req.data || {};
  if (!Number.isInteger(amount) || amount < 10000 || amount > 10_000_000)
    throw new HttpsError("invalid-argument","Nominal tidak valid");
  if (!idempotencyKey) throw new HttpsError("invalid-argument","idempotencyKey wajib");
  const uid = req.auth.uid;

  const idemRef = db.ref(`idempotency/${uid}/topup-${idempotencyKey}`);
  const ex = await idemRef.get();
  if (ex.exists()) return ex.val();

  const requestId = db.ref("paymentRequests").push().key;
  const refNum = "TOP" + crypto.randomBytes(5).toString("hex").toUpperCase();
  const now = Date.now();

  await db.ref(`paymentRequests/${requestId}`).set({
    requestId, userId: uid, provider: "PENDING_INTEGRATION",
    method: method || "qris", amount, status: "pending",
    providerReference: refNum, createdAt: now, expiresAt: now + 30 * 60 * 1000
  });

  const result = {
    requestId, referenceNumber: refNum, amount, method,
    expiresAt: now + 30 * 60 * 1000,
    instructions: "Integrasi payment gateway belum dikonfigurasi. Hubungi admin untuk mengaktifkan metode pembayaran."
  };
  await idemRef.set(result);
  return result;
});

/* ====== WITHDRAWAL ====== */
exports.requestWithdrawal = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const { amount, bank, accountNumber, accountName, idempotencyKey } = req.data || {};
  if (!Number.isInteger(amount) || amount < 10000 || amount > 10_000_000)
    throw new HttpsError("invalid-argument","Nominal tidak valid");
  if (!bank || !accountName) throw new HttpsError("invalid-argument","Data rekening tidak lengkap");
  if (!/^\d{6,20}$/.test(accountNumber)) throw new HttpsError("invalid-argument","Nomor rekening tidak valid");
  if (!idempotencyKey) throw new HttpsError("invalid-argument","idempotencyKey wajib");
  const uid = req.auth.uid;

  const idemRef = db.ref(`idempotency/${uid}/wd-${idempotencyKey}`);
  const ex = await idemRef.get();
  if (ex.exists()) return ex.val();

  await ensureWallet(uid);
  const wdId = db.ref("withdrawals").push().key;
  const refNum = "WD" + crypto.randomBytes(5).toString("hex").toUpperCase();
  const now = Date.now();

  await db.ref().transaction(async txn => {
    const s = await txn.get(db.ref(`wallets/${uid}`));
    const bal = s.val().availableBalance || 0;
    if (bal < amount) throw new HttpsError("failed-precondition","Saldo tidak cukup");
    txn.set(db.ref(`withdrawals/${wdId}`), {
      withdrawalId: wdId, userId: uid, amount, fee: 0,
      bank, accountNumber, accountName, status: "pending",
      referenceNumber: refNum, createdAt: now, updatedAt: now
    });
    txn.update(db.ref(`wallets/${uid}`), {
      availableBalance: bal - amount,
      pendingBalance: (s.val().pendingBalance || 0) + amount,
      updatedAt: now
    });
    txn.set(db.ref(`notifications/${uid}`).push(), {
      title: "Penarikan diproses",
      message: `Permintaan penarikan ${amount} sedang ditinjau.`,
      type: "withdrawal", read: false, createdAt: now, link: "activity"
    });
  });

  const result = { withdrawalId: wdId, referenceNumber: refNum };
  await idemRef.set(result);
  return result;
});

/* ====== PAY MERCHANT ====== */
exports.payMerchant = onCall({ region: REGION }, async req => {
  requireAuth(req);
  const { code, amount, idempotencyKey } = req.data || {};
  if (!code || !Number.isInteger(amount) || amount < 1000 || amount > 10_000_000)
    throw new HttpsError("invalid-argument","Data tidak valid");
  if (!idempotencyKey) throw new HttpsError("invalid-argument","idempotencyKey wajib");
  const uid = req.auth.uid;

  const idemRef = db.ref(`idempotency/${uid}/pay-${idempotencyKey}`);
  const ex = await idemRef.get();
  if (ex.exists()) return ex.val();

  const mSnap = await db.ref(`merchants/${code}`).get();
  if (!mSnap.exists()) throw new HttpsError("not-found","Merchant tidak terdaftar");

  await ensureWallet(uid);
  const txId = db.ref("transactions").push().key;
  const refNum = "PAY" + crypto.randomBytes(5).toString("hex").toUpperCase();
  const now = Date.now();

  await db.ref().transaction(async txn => {
    const s = await txn.get(db.ref(`wallets/${uid}`));
    const bal = s.val().availableBalance || 0;
    if (bal < amount) throw new HttpsError("failed-precondition","Saldo tidak cukup");
    txn.set(db.ref(`transactions/${txId}`), {
      userId: uid, senderId: uid, receiverId: code,
      transactionType: "PAYMENT", amount, fee: 0, status: "success",
      createdAt: now, updatedAt: now, referenceNumber: refNum,
      description: "Pembayaran ke " + code, idempotencyKey
    });
    txn.update(db.ref(`wallets/${uid}`), { availableBalance: bal - amount, updatedAt: now });
    txn.set(db.ref(`notifications/${uid}`).push(), {
      title: "Pembayaran berhasil",
      message: `${amount} ke ${code}`,
      type: "payment", read: false, createdAt: now, link: "activity"
    });
  });

  const result = { transactionId: txId, referenceNumber: refNum };
  await idemRef.set(result);
  return result;
});

/* ====== QRIS stubs ====== */
exports.payQris = onCall({ region: REGION }, async () => {
  throw new HttpsError("failed-precondition","Integrasi QRIS belum dikonfigurasi.");
});
exports.createQrisCode = onCall({ region: REGION }, async () => {
  throw new HttpsError("failed-precondition","Integrasi QRIS belum dikonfigurasi.");
});

/* ====== VERIFICATION EMAIL (opsional, butuh email service) ====== */
exports.sendVerificationEmail = onCall({ region: REGION }, async req => {
  requireAuth(req);
  // Firebase otomatis kirim verifikasi saat sign-up; untuk Google-only, email sudah terverifikasi.
  return { ok: true, message: "Email Google Anda sudah terverifikasi." };
});
