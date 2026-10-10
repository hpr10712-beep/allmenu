const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();
const db = admin.database();

// 1. Set custom claim role (dipanggil oleh superadmin via HTTPS Callable)
exports.setUserRole = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Login diperlukan");
  const caller = await admin.auth().getUser(context.auth.uid);
  if (caller.customClaims?.role !== "superadmin") {
    throw new functions.https.HttpsError("permission-denied", "Hanya superadmin");
  }
  await admin.auth().setCustomUserClaims(data.uid, { role: data.role });
  await db.ref(`users/${data.uid}/role`).set(data.role);
  return { ok: true };
});

// 2. Auto-submit ujian ketika waktu habis
exports.autoSubmitExpiredAttempts = functions.pubsub.schedule("every 5 minutes").onRun(async () => {
  const now = Date.now();
  const snap = await db.ref("examAttempts").once("value");
  const data = snap.val() || {};
  for (const examId of Object.keys(data)) {
    for (const uid of Object.keys(data[examId])) {
      for (const attemptId of Object.keys(data[examId][uid])) {
        const a = data[examId][uid][attemptId];
        if (!a.submitted && a.endsAt && a.endsAt < now) {
          await db.ref(`examAttempts/${examId}/${uid}/${attemptId}`).update({ submitted: true, submittedAt: now, auto: true });
          // Hitung nilai di sini...
        }
      }
    }
  }
});

// 3. Approve user (memerlukan Admin SDK untuk aktifkan akun)
exports.approveUser = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Login diperlukan");
  const caller = await admin.auth().getUser(context.auth.uid);
  if (!["admin","superadmin"].includes(caller.customClaims?.role)) {
    throw new functions.https.HttpsError("permission-denied", "Hanya admin");
  }
  await admin.auth().updateUser(data.uid, { disabled: false });
  await db.ref(`users/${data.uid}/status`).set("active");
  return { ok: true };
});

// 4. Menghitung nilai resmi (dijalankan saat submit, di server)
exports.gradeSubmission = functions.https.onCall(async (data, context) => {
  if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Login diperlukan");
  // ... verifikasi, hitung, simpan ke examResults ...
});
