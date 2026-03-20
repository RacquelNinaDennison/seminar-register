const { onCall, HttpsError } = require("firebase-functions/v2/https");
const { getFirestore } = require("firebase-admin/firestore");
const { initializeApp } = require("firebase-admin/app");
const crypto = require("crypto");

initializeApp();
const db = getFirestore();

exports.verifyTAPassword = onCall(async (request) => {
  const password = request.data.password;

  if (!password || typeof password !== "string") {
    throw new HttpsError("invalid-argument", "Password is required.");
  }

  const configSnap = await db.collection("config").doc("ta").get();

  if (!configSnap.exists) {
    throw new HttpsError("not-found", "TA config not found.");
  }

  const storedHash = configSnap.data().passwordHash;

  // Hash the submitted password the same way and compare
  const hash = crypto.createHash("sha256").update(password).digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash))) {
    throw new HttpsError("permission-denied", "Incorrect password.");
  }

  return { success: true };
});
