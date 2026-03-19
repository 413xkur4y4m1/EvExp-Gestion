'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const admin = require('firebase-admin');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');

dotenv.config();

const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const APP_URL = firstDefined(
  process.env.APP_URL,
  process.env.NEXT_PUBLIC_APP_URL,
  process.env.NEXTAUTH_URL,
  `http://localhost:${PORT}`
);
const CRON_SECRET = process.env.CRON_SECRET || '';
const AZURE_TENANT_ID = firstDefined(process.env.AZURE_TENANT_ID, process.env.TENANT_ID);
const AZURE_CLIENT_ID = firstDefined(process.env.AZURE_CLIENT_ID, process.env.CLIENT_ID);
const AZURE_CLIENT_SECRET = firstDefined(process.env.AZURE_CLIENT_SECRET, process.env.CLIENT_SECRET);
const AZURE_SCOPE = firstDefined(
  process.env.AZURE_SCOPE,
  'openid profile email User.Read'
);
const AZURE_REDIRECT_URI = firstDefined(
  process.env.AZURE_REDIRECT_URI,
  `${APP_URL.replace(/\/+$/, '')}/auth/microsoft/callback`
);

const ADMIN_SESSION_COOKIE = '__session';
const STUDENT_SESSION_COOKIE = '__student_session';
const AZURE_STATE_COOKIE = '__azure_oauth_state';
const AZURE_NONCE_COOKIE = '__azure_oauth_nonce';
const AZURE_REDIRECT_COOKIE = '__azure_oauth_redirect';
const DEFAULT_STUDENT_REDIRECT = '/app/dashboard-estudiante.html';

const firebaseApp = initializeFirebaseAdmin();
const db = firebaseApp.firestore();
const rtdb = safeGetRealtimeDatabase(firebaseApp);

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors(buildCorsConfig()));

const FRONTEND_DIR = path.resolve(__dirname, 'frontend');
if (fs.existsSync(FRONTEND_DIR)) {
  app.use('/app', express.static(FRONTEND_DIR));
  app.get('/portal', (_req, res) => {
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
  });
}

function firstDefined(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return value;
    }
  }
  return '';
}

function getServiceAccountConfig() {
  const jsonCandidate = firstDefined(
    process.env.FIREBASE_SERVICE_ACCOUNT_KEY,
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  );
  if (jsonCandidate) {
    try {
      return normalizeServiceAccount(JSON.parse(jsonCandidate));
    } catch (_error) {}
  }

  const b64Candidate = firstDefined(
    process.env.FIREBASE_SERVICE_ACCOUNT_KEY_B64,
    process.env.SERVICE_ACCOUNT_KEY_B64
  );
  if (b64Candidate) {
    try {
      const decoded = Buffer.from(b64Candidate, 'base64').toString('utf8');
      return normalizeServiceAccount(JSON.parse(decoded));
    } catch (_error) {}
  }

  const fileCandidates = [
    process.env.FIREBASE_SERVICE_ACCOUNT_FILE,
    path.resolve(process.cwd(), 'serviceAccountKey.json'),
    path.resolve(process.cwd(), 'serviceAccountKey.b64'),
    path.resolve(process.cwd(), 'LaSalleGestionaDonFlutter-main', 'serviceAccountKey.b64'),
    path.resolve(process.cwd(), 'LaSalleGestionaDonFlutter-main', 'serviceAccountKey.json'),
  ].filter(Boolean);

  for (const filePath of fileCandidates) {
    if (!fs.existsSync(filePath)) continue;
    try {
      const raw = fs.readFileSync(filePath, 'utf8').trim();
      const maybeJson = filePath.endsWith('.b64')
        ? Buffer.from(raw, 'base64').toString('utf8')
        : raw;
      return normalizeServiceAccount(JSON.parse(maybeJson));
    } catch (_error) {}
  }

  const projectId = firstDefined(
    process.env.FIREBASE_PROJECT_ID,
    process.env.GOOGLE_PROJECT_ID,
    process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID
  );
  const clientEmail = firstDefined(
    process.env.FIREBASE_CLIENT_EMAIL,
    process.env.GOOGLE_CLIENT_EMAIL
  );
  const privateKeyRaw = firstDefined(
    process.env.FIREBASE_PRIVATE_KEY,
    process.env.GOOGLE_PRIVATE_KEY
  );
  const privateKey = privateKeyRaw ? privateKeyRaw.replace(/\\n/g, '\n') : '';

  if (projectId && clientEmail && privateKey) {
    return { projectId, clientEmail, privateKey };
  }

  throw new Error(
    'No se encontro configuracion de Firebase Admin. Define FIREBASE_SERVICE_ACCOUNT_KEY JSON, B64 o archivo serviceAccountKey.b64.'
  );
}

function normalizeServiceAccount(raw) {
  return {
    projectId: raw.projectId || raw.project_id,
    clientEmail: raw.clientEmail || raw.client_email,
    privateKey: String(raw.privateKey || raw.private_key || '').replace(/\\n/g, '\n'),
  };
}

function initializeFirebaseAdmin() {
  if (admin.apps.length) {
    return admin.app();
  }

  const serviceAccount = getServiceAccountConfig();
  const databaseURL = firstDefined(
    process.env.FIREBASE_DATABASE_URL,
    process.env.NEXT_PUBLIC_FIREBASE_DATABASE_URL
  );

  const options = {
    credential: admin.credential.cert(serviceAccount),
  };
  if (databaseURL) {
    options.databaseURL = databaseURL;
  }

  admin.initializeApp(options);
  return admin.app();
}

function safeGetRealtimeDatabase(appInstance) {
  try {
    return appInstance.database();
  } catch (_error) {
    return null;
  }
}

function buildCorsConfig() {
  const rawOrigins = firstDefined(
    process.env.CORS_ORIGIN,
    process.env.FRONTEND_URL,
    process.env.NEXT_PUBLIC_APP_URL,
    process.env.APP_URL
  );
  if (!rawOrigins) {
    return { origin: true, credentials: true };
  }

  const allowedOrigins = rawOrigins
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

  return {
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error(`Origen no permitido por CORS: ${origin}`));
    },
    credentials: true,
  };
}

function asyncHandler(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

function toDate(value) {
  if (!value) return null;
  if (value instanceof Date) return value;
  if (typeof value.toDate === 'function') {
    try {
      return value.toDate();
    } catch (_error) {
      return null;
    }
  }
  if (typeof value === 'number') {
    const numericDate = new Date(value);
    return Number.isNaN(numericDate.getTime()) ? null : numericDate;
  }
  if (typeof value === 'string') {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  return null;
}

function toISO(value) {
  const date = toDate(value);
  return date ? date.toISOString() : null;
}

function toTimestamp(value) {
  const date = toDate(value);
  if (!date) return null;
  return admin.firestore.Timestamp.fromDate(date);
}

function randomHex(size) {
  return crypto.randomBytes(size).toString('hex');
}

function generateNumericCode(length) {
  const min = 10 ** (length - 1);
  const max = (10 ** length) - 1;
  return String(Math.floor(min + Math.random() * (max - min)));
}

function generateLoanCode(grupo) {
  return `PRST-${String(grupo || 'SG').toUpperCase()}-${generateNumericCode(5)}`;
}

function generateDebtCode(grupo) {
  return `ADEU-${String(grupo || 'XXX').toUpperCase()}-${generateNumericCode(5)}`;
}

function generatePaymentCode(grupo) {
  return `PAGO-${String(grupo || 'XXX').toUpperCase()}-${generateNumericCode(5)}`;
}

function normalizeQrData(rawValue) {
  let value = String(rawValue || '').trim();
  if (!value) return '';

  if (value.includes('://')) {
    const sanitized = value.split('#')[0];
    const lastChunk = sanitized.split('/').pop() || '';
    value = lastChunk.split('?')[0] || '';
  }
  return value.trim();
}

function getCookieFromHeader(req, name) {
  const cookieHeader = req.headers.cookie || '';
  const parts = cookieHeader.split(';').map((part) => part.trim());
  for (const part of parts) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key === name) return value;
  }
  return '';
}

function decodeSessionCookie(value) {
  try {
    const decoded = Buffer.from(value, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (_error) {
    return null;
  }
}

function encodeSessionCookie(payload) {
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function decodeJwtPayload(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length < 2) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch (_error) {
    return null;
  }
}

function isAllowedStudentEmail(email) {
  const value = String(email || '').trim().toLowerCase();
  return value.endsWith('@alumnos.uacj.mx') || value.endsWith('@ulsaneza.edu.mx');
}

function createDeterministicStudentUid(email) {
  const safe = String(email || '').trim().toLowerCase();
  if (!safe) return '';
  return 'STD_' + crypto.createHash('sha256').update(safe).digest('hex').slice(0, 24).toUpperCase();
}

function setCookie(res, name, value, maxAgeMs) {
  res.cookie(name, value, {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: maxAgeMs,
    path: '/',
  });
}

function clearCookie(res, name) {
  res.clearCookie(name, {
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  });
}

function clearAzureOauthCookies(res) {
  clearCookie(res, AZURE_STATE_COOKIE);
  clearCookie(res, AZURE_NONCE_COOKIE);
  clearCookie(res, AZURE_REDIRECT_COOKIE);
}

function getLoginRedirectWithError(message) {
  const safeMessage = encodeURIComponent(String(message || 'No se pudo iniciar sesion con Microsoft.'));
  return `/app/login-estudiante.html?ms_error=${safeMessage}`;
}

function getStudentSessionFromRequest(req) {
  const cookieValue =
    req.cookies?.[STUDENT_SESSION_COOKIE] ||
    getCookieFromHeader(req, STUDENT_SESSION_COOKIE);

  if (!cookieValue) {
    return { ok: false, status: 401, message: 'No hay sesion de estudiante.' };
  }

  const sessionData = decodeSessionCookie(cookieValue);
  if (!sessionData || !sessionData.id || !sessionData.email) {
    return { ok: false, status: 403, message: 'Sesion de estudiante invalida.' };
  }

  if (Date.now() > Number(sessionData.expiresAt || 0)) {
    return { ok: false, status: 401, message: 'Sesion de estudiante expirada.' };
  }

  return {
    ok: true,
    claims: {
      id: String(sessionData.id || ''),
      name: String(sessionData.name || 'Estudiante'),
      email: String(sessionData.email || '').toLowerCase(),
      grupo: String(sessionData.grupo || ''),
      provider: String(sessionData.provider || 'azure'),
    },
  };
}

async function verifyAdminSessionFromRequest(req) {
  const cookieValue =
    req.cookies?.[ADMIN_SESSION_COOKIE] ||
    getCookieFromHeader(req, ADMIN_SESSION_COOKIE);
  if (!cookieValue) {
    return { ok: false, status: 401, message: 'No autorizado: no hay sesion.' };
  }

  const sessionData = decodeSessionCookie(cookieValue);
  if (!sessionData) {
    return { ok: false, status: 403, message: 'No autorizado: sesion invalida.' };
  }

  if (!sessionData.admin || !sessionData.uid) {
    return { ok: false, status: 403, message: 'No autorizado: sesion sin permisos admin.' };
  }

  if (Date.now() > Number(sessionData.expiresAt || 0)) {
    return { ok: false, status: 401, message: 'No autorizado: sesion expirada.' };
  }

  const adminDoc = await db.collection('admins').doc(sessionData.uid).get();
  if (!adminDoc.exists) {
    return { ok: false, status: 403, message: 'No autorizado: admin no encontrado.' };
  }

  const adminData = adminDoc.data() || {};
  return {
    ok: true,
    claims: {
      uid: sessionData.uid,
      admin: true,
      email: adminData.correo || '',
    },
  };
}

async function requireAdmin(req, res, next) {
  const validation = await verifyAdminSessionFromRequest(req);
  if (!validation.ok) {
    return res.status(validation.status).json({ message: validation.message });
  }

  req.adminClaims = validation.claims;
  return next();
}

function requireCron(req, res, next) {
  if (!CRON_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'CRON_SECRET no esta configurado.',
    });
  }

  const authHeader = req.get('Authorization') || req.get('authorization');
  if (authHeader !== `Bearer ${CRON_SECRET}`) {
    return res.status(401).json({ success: false, message: 'No autorizado.' });
  }

  return next();
}

let emailTransporter;
function getEmailTransporter() {
  if (emailTransporter !== undefined) return emailTransporter;

  const emailUser = process.env.EMAIL_USER;
  const emailPassword = process.env.EMAIL_PASSWORD;
  if (!emailUser || !emailPassword) {
    emailTransporter = null;
    return emailTransporter;
  }

  emailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp-mail.outlook.com',
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: {
      user: emailUser,
      pass: emailPassword,
    },
    tls: {
      ciphers: 'SSLv3',
      rejectUnauthorized: false,
    },
  });

  return emailTransporter;
}

async function sendEmail(options) {
  const transporter = getEmailTransporter();
  if (!transporter) {
    console.warn('[EMAIL] Transporte SMTP no configurado.');
    return { success: false, error: new Error('SMTP_NOT_CONFIGURED') };
  }

  try {
    const info = await transporter.sendMail(options);
    return { success: true, info };
  } catch (error) {
    console.error('[EMAIL] Error enviando correo:', error.message);
    return { success: false, error };
  }
}

function emailFrom(displayName) {
  const emailUser = process.env.EMAIL_USER || 'noreply@localhost';
  return `"${displayName}" <${emailUser}>`;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function extractGrupoFromEmail(email) {
  if (!email) return null;
  const match = String(email).match(/^al\.(.+?)\d+@alumnos\.uacj\.mx$/i);
  return match ? String(match[1]).toUpperCase() : null;
}

async function ensureSubcollectionsExist(studentRef) {
  const subcollections = ['Prestamos', 'Adeudos', 'Pagados', 'Completados', 'Formularios', 'Notificaciones'];
  for (const subcollectionName of subcollections) {
    const subcollectionRef = studentRef.collection(subcollectionName);
    const snapshot = await subcollectionRef.limit(1).get();
    if (snapshot.empty) {
      await subcollectionRef.doc('_placeholder').set({ info: 'Coleccion inicializada.' });
    }
  }
}

async function createOrUpdateStudentServer(user) {
  const uid = String(user.id || '').trim();
  if (!uid) {
    throw new Error('Se requiere un ID para crear o actualizar el estudiante.');
  }

  const studentRef = db.collection('Estudiantes').doc(uid);
  const studentSnap = await studentRef.get();

  const grupoFromEmail = extractGrupoFromEmail(user.email);
  const grupo = user.grupo || grupoFromEmail || '';
  const rol = user.rol || 'estudiante';

  if (!studentSnap.exists) {
    await studentRef.set({
      uid,
      nombre: user.name || '',
      correo: user.email || '',
      rol,
      grupo,
      carrera: user.carrera || 'turismo',
      fotoPerfil: user.image || '',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
      prestamos: [],
      adeudos: [],
      pagos: [],
      completados: [],
    });
  } else {
    const currentData = studentSnap.data() || {};
    await studentRef.update({
      nombre: user.name || currentData.nombre || '',
      fotoPerfil: user.image || currentData.fotoPerfil || '',
      grupo: grupo || currentData.grupo || '',
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
    });
  }

  await ensureSubcollectionsExist(studentRef);
}

async function findStudentByEmail(email) {
  const snapshot = await db
    .collection('Estudiantes')
    .where('correo', '==', email)
    .limit(1)
    .get();

  if (snapshot.empty) return null;
  const doc = snapshot.docs[0];
  return { id: doc.id, data: doc.data() };
}

async function findLoanByQRToken(qrToken) {
  const studentsSnapshot = await db.collection('Estudiantes').get();
  for (const studentDoc of studentsSnapshot.docs) {
    const loanSnapshot = await studentDoc.ref
      .collection('Prestamos')
      .where('qrToken', '==', qrToken)
      .limit(1)
      .get();

    if (!loanSnapshot.empty) {
      return {
        studentId: studentDoc.id,
        studentData: studentDoc.data() || {},
        loanDoc: loanSnapshot.docs[0],
        loanData: loanSnapshot.docs[0].data() || {},
      };
    }
  }
  return null;
}

async function findAdeudoByToken(token, tokenField) {
  const studentsSnapshot = await db.collection('Estudiantes').get();
  for (const studentDoc of studentsSnapshot.docs) {
    const adeudoSnapshot = await studentDoc.ref
      .collection('Adeudos')
      .where(tokenField, '==', token)
      .limit(1)
      .get();

    if (!adeudoSnapshot.empty) {
      return {
        studentId: studentDoc.id,
        studentData: studentDoc.data() || {},
        adeudoDoc: adeudoSnapshot.docs[0],
        adeudoData: adeudoSnapshot.docs[0].data() || {},
      };
    }
  }
  return null;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function generateQRCodeDataURL(text, size = 300) {
  const encodedText = encodeURIComponent(text);
  return `https://quickchart.io/qr?text=${encodedText}&size=${size}&margin=1`;
}

function defaultStatsPayload() {
  return {
    topMateriales: [],
    topPerdidos: [],
    topEstudiantes: [],
    peoresEstudiantes: [],
    totalPrestamos: 0,
    totalAdeudos: 0,
    totalCompletados: 0,
    totalEstudiantes: 0,
    analisisIA: {
      resumen_ejecutivo: 'Aun no hay datos disponibles.',
      insights: [],
      predicciones: [],
      recomendaciones: [],
      alertas: [],
      tendencias: [],
    },
    ultimaActualizacion: null,
    ultimaActualizacionIA: null,
    version: Date.now(),
  };
}

function createOtpHtmlBody(otp) {
  return `
  <div style="font-family: Arial, sans-serif; color: #333; line-height: 1.5;">
    <div style="max-width: 560px; margin: 24px auto; padding: 24px; border: 1px solid #e5e7eb; border-radius: 12px;">
      <h1 style="color: #0a1c65; margin-top: 0;">Sistema La Salle</h1>
      <p>Tu codigo de acceso es:</p>
      <div style="text-align: center; background: #f3f4f6; padding: 16px; border-radius: 8px; margin: 16px 0;">
        <span style="font-size: 34px; letter-spacing: 4px; font-weight: bold; color: #e10022;">${otp}</span>
      </div>
      <p>Este codigo vence en 15 minutos.</p>
    </div>
  </div>`;
}

function createAdminCredentialsHtml(adminAccount, temporaryPassword) {
  return `
  <div style="font-family: Arial, sans-serif; padding: 20px;">
    <h2>Credenciales de administrador</h2>
    <p>Tu cuenta fue creada correctamente.</p>
    <p><strong>AdminOT Account:</strong> ${adminAccount}</p>
    <p><strong>Password temporal:</strong> ${temporaryPassword}</p>
    <p>Por seguridad, usa OTP para entrar y no compartas esta informacion.</p>
  </div>`;
}

function createOverdueLoanHtmlBody({ studentName, materialName, loanDate, returnDate }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const loanDateLabel = loanDate ? loanDate.toLocaleDateString('es-MX') : '-';
  const returnDateLabel = returnDate ? returnDate.toLocaleDateString('es-MX') : '-';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #dc2626; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Adeudo por Prestamo Vencido</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Se detecto un prestamo vencido y se genero un adeudo en tu cuenta.</p>

      <div style="background-color: #fee2e2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Fecha de prestamo:</strong> ${loanDateLabel}</p>
        <p style="margin: 5px 0;"><strong>Fecha de devolucion esperada:</strong> ${returnDateLabel}</p>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px;">
          Revisa tus adeudos para decidir si devolveras el material o liquidaras el pago correspondiente.
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Por favor no respondas a este mensaje.
      </p>
    </div>
  </div>`;
}

function createPaymentSuccessHtml({ studentName, materialName, amount, paymentCode, transactionId }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeAmount = Number(amount || 0).toFixed(2);
  const safePaymentCode = paymentCode || '-';
  const safeTx = transactionId || '-';
  const nowLabel = new Date().toLocaleString('es-MX');

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Pago Exitoso</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Tu pago ha sido procesado exitosamente y tu adeudo fue liquidado.</p>

      <div style="background-color: #d1fae5; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #10b981;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Monto pagado:</strong> $${safeAmount} MXN</p>
        <p style="margin: 5px 0;"><strong>Codigo de pago:</strong> ${safePaymentCode}</p>
        <p style="margin: 5px 0;"><strong>ID de transaccion:</strong> ${safeTx}</p>
        <p style="margin: 5px 0;"><strong>Fecha:</strong> ${nowLabel}</p>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px;">
          Estado actualizado: tu adeudo aparece como <strong>PAGADO</strong>.
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Conserva este mensaje como comprobante.
      </p>
    </div>
  </div>`;
}

function createLoanReturnConfirmedHtml({ studentName, materialName, quantity }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeQuantity = Number(quantity || 0);

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Devolucion Confirmada</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>La devolucion fue registrada correctamente.</p>

      <div style="background-color: #d1fae5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Estado:</strong> Devuelto</p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Gracias por mantener tu historial al corriente.
      </p>
    </div>
  </div>`;
}

function createDebtReturnConfirmedHtml({ studentName, materialName, quantity, code }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeQuantity = Number(quantity || 0);
  const safeCode = code || '-';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Material Devuelto - Adeudo Resuelto</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Se confirmo la devolucion del material asociado a tu adeudo.</p>

      <div style="background-color: #d1fae5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Codigo:</strong> ${safeCode}</p>
        <p style="margin: 5px 0;"><strong>Estado:</strong> Devuelto - Resuelto</p>
      </div>

      <p style="margin-top: 20px;">Ya no tienes pendientes por este adeudo.</p>
    </div>
  </div>`;
}

function createDebtPaymentConfirmedHtml({ studentName, materialName, amount, paymentCode }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeAmount = Number(amount || 0).toFixed(2);
  const safePaymentCode = paymentCode || '-';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Pago Confirmado</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>El pago presencial fue confirmado correctamente.</p>

      <div style="background-color: #d1fae5; padding: 15px; border-radius: 8px; margin: 20px 0;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Monto:</strong> $${safeAmount} MXN</p>
        <p style="margin: 5px 0;"><strong>Codigo de pago:</strong> ${safePaymentCode}</p>
        <p style="margin: 5px 0;"><strong>Estado:</strong> Pagado</p>
      </div>

      <p>Tu adeudo fue liquidado. Gracias por completar el proceso.</p>
    </div>
  </div>`;
}

function createDebtGeneratedHtml({ studentName, materialName, quantity, amount, debtCode, dueDate }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeQuantity = Number(quantity || 0);
  const safeAmount = Number(amount || 0).toFixed(2);
  const safeCode = debtCode || '-';
  const dueDateLabel = dueDate ? dueDate.toLocaleString('es-MX') : '-';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #dc2626; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Nuevo Adeudo Generado</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Se genero un adeudo porque el material no fue devuelto a tiempo.</p>

      <div style="background-color: #fee2e2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Monto estimado:</strong> $${safeAmount} MXN</p>
        <p style="margin: 5px 0;"><strong>Codigo de adeudo:</strong> ${safeCode}</p>
        <p style="margin: 5px 0;"><strong>Fecha de vencimiento original:</strong> ${dueDateLabel}</p>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px;">
          Opciones: devuelve el material en laboratorio o realiza el pago para liquidar el adeudo.
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Por favor no respondas a este mensaje.
      </p>
    </div>
  </div>`;
}

function createReminderHtml({ studentName, materialName, quantity, returnDate, code }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeQuantity = Number(quantity || 0);
  const safeCode = code || '-';
  const returnDateLabel = returnDate
    ? returnDate.toLocaleString('es-MX', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
    : '-';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #f59e0b; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Recordatorio de Devolucion</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Tu prestamo vence en menos de 24 horas. Devuelvelo a tiempo para evitar adeudos.</p>

      <div style="background-color: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Fecha de devolucion:</strong> ${returnDateLabel}</p>
        <p style="margin: 5px 0;"><strong>Codigo:</strong> ${safeCode}</p>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px;">
          Usa tu QR de devolucion en laboratorio para completar el proceso.
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Por favor no respondas a este mensaje.
      </p>
    </div>
  </div>`;
}

function createFormRequestHtml({ studentName, materialName, quantity, debtCode, question, options, formUrl, qrImageUrl }) {
  const student = studentName || 'Estudiante';
  const material = materialName || 'Material';
  const safeQuantity = Number(quantity || 0);
  const safeCode = debtCode || '-';
  const safeQuestion = question || 'Que sucedio con el material?';
  const safeOptions = Array.isArray(options) ? options : [];

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #7c3aed; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Formulario de Seguimiento</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Necesitamos tu respuesta para avanzar con la resolucion de tu adeudo.</p>

      <div style="background-color: #fee2e2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Codigo de adeudo:</strong> ${safeCode}</p>
      </div>

      <div style="background-color: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
        <p style="margin: 0; font-size: 14px;"><strong>Pregunta:</strong><br/>"${safeQuestion}"</p>
      </div>

      <div style="background-color: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; border: 3px solid #7c3aed;">
        <p style="margin-bottom: 15px; font-size: 16px;"><strong>Escanea este QR para responder:</strong></p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; display: inline-block;">
          <img src="${qrImageUrl}" alt="Codigo QR del formulario" style="max-width: 300px; width: 100%; height: auto; display: block;" />
        </div>
        <p style="font-size: 14px; color: #374151; margin: 15px 0;"><strong>O usa el enlace directo:</strong></p>
        <a href="${formUrl}" style="background-color: #7c3aed; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
          Completar formulario
        </a>
      </div>

      <div style="background-color: #e0e7ff; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #6366f1;">
        <p style="margin: 0; font-size: 14px; line-height: 1.7;">
          <strong>Opciones disponibles:</strong><br/>
          ${safeOptions.map((option, index) => `${index + 1}. ${option}`).join('<br/>')}
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Por favor no respondas a este mensaje.
      </p>
    </div>
  </div>`;
}

function createFormReturnQrHtml({ nombreEstudiante, nombreMaterial, cantidad, codigoAdeudo, qrUrl }) {
  const student = nombreEstudiante || 'Estudiante';
  const material = nombreMaterial || 'Material';
  const safeQuantity = Number(cantidad || 0);
  const safeCode = codigoAdeudo || '-';
  const qrImageUrl = generateQRCodeDataURL(qrUrl);

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Codigo QR de Devolucion</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Registramos tu respuesta y te enviamos tu QR para devolver el material.</p>

      <div style="background-color: #fef3c7; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #f59e0b;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Codigo de adeudo:</strong> ${safeCode}</p>
      </div>

      <div style="background-color: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; border: 3px solid #10b981;">
        <p style="margin-bottom: 15px; font-size: 16px;"><strong>Tu codigo QR de devolucion:</strong></p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; display: inline-block;">
          <img src="${qrImageUrl}" alt="Codigo QR de devolucion" style="max-width: 300px; width: 100%; height: auto; display: block;" />
        </div>
        <p style="font-size: 11px; color: #6b7280; margin-top: 15px; padding: 10px; background-color: #f9fafb; border-radius: 4px; word-break: break-all; font-family: monospace;">
          ${qrUrl}
        </p>
      </div>

      <p style="color: #6b7280; font-size: 12px; margin-top: 30px; text-align: center; border-top: 1px solid #e5e7eb; padding-top: 15px;">
        Este es un correo automatico del Sistema de Prestamos de Laboratorio.<br/>
        Por favor no respondas a este mensaje.
      </p>
    </div>
  </div>`;
}

function createFormPaymentLinkHtml({ nombreEstudiante, nombreMaterial, cantidad, monto, respuesta, paymentUrl }) {
  const student = nombreEstudiante || 'Estudiante';
  const material = nombreMaterial || 'Material';
  const safeQuantity = Number(cantidad || 0);
  const safeAmount = Number(monto || 0).toFixed(2);
  const safeAnswer = respuesta || 'No definida';

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #3b82f6; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Realizar Pago en Linea</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Registramos tu respuesta: <strong>"${safeAnswer}"</strong>.</p>

      <div style="background-color: #fee2e2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Monto a pagar:</strong> $${safeAmount} MXN</p>
      </div>

      <div style="text-align: center; margin: 30px 0;">
        <a href="${paymentUrl}" style="background-color: #3b82f6; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; display: inline-block; font-weight: bold;">
          Pagar ahora
        </a>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px;">
          Una vez completado el pago, tu adeudo se actualizara automaticamente.
        </p>
      </div>
    </div>
  </div>`;
}

function createFormPaymentQrHtml({ nombreEstudiante, nombreMaterial, cantidad, monto, codigoAdeudo, respuesta, qrUrl }) {
  const student = nombreEstudiante || 'Estudiante';
  const material = nombreMaterial || 'Material';
  const safeQuantity = Number(cantidad || 0);
  const safeAmount = Number(monto || 0).toFixed(2);
  const safeCode = codigoAdeudo || '-';
  const safeAnswer = respuesta || 'No definida';
  const qrImageUrl = generateQRCodeDataURL(qrUrl);

  return `
  <div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px; margin: 0 auto;">
    <div style="background-color: #10b981; padding: 20px; border-radius: 8px 8px 0 0; text-align: center;">
      <h2 style="color: white; margin: 0;">Codigo QR de Pago Presencial</h2>
    </div>

    <div style="background-color: #f9fafb; padding: 20px; border-radius: 0 0 8px 8px;">
      <p>Hola <strong>${student}</strong>,</p>
      <p>Registramos tu respuesta: <strong>"${safeAnswer}"</strong>.</p>

      <div style="background-color: #fee2e2; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #dc2626;">
        <p style="margin: 5px 0;"><strong>Material:</strong> ${material}</p>
        <p style="margin: 5px 0;"><strong>Cantidad:</strong> ${safeQuantity}</p>
        <p style="margin: 5px 0;"><strong>Monto a pagar:</strong> $${safeAmount} MXN</p>
        <p style="margin: 5px 0;"><strong>Codigo de adeudo:</strong> ${safeCode}</p>
      </div>

      <div style="background-color: white; padding: 25px; border-radius: 8px; margin: 20px 0; text-align: center; border: 3px solid #10b981;">
        <p style="margin-bottom: 15px; font-size: 16px;"><strong>Tu codigo QR de pago:</strong></p>
        <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; display: inline-block;">
          <img src="${qrImageUrl}" alt="Codigo QR de pago presencial" style="max-width: 300px; width: 100%; height: auto; display: block;" />
        </div>
        <p style="font-size: 11px; color: #6b7280; margin-top: 15px; padding: 10px; background-color: #f9fafb; border-radius: 4px; word-break: break-all; font-family: monospace;">
          ${qrUrl}
        </p>
      </div>

      <div style="background-color: #dbeafe; padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #3b82f6;">
        <p style="margin: 0; font-size: 14px; line-height: 1.8;">
          Instrucciones: presenta este codigo en caja, realiza el pago y espera la confirmacion del encargado.
        </p>
      </div>
    </div>
  </div>`;
}

function buildBasicAnalysisFromStats(statsData) {
  const totalPrestamos = Number(statsData.totalPrestamos || 0);
  const totalAdeudos = Number(statsData.totalAdeudos || 0);
  const totalCompletados = Number(statsData.totalCompletados || 0);
  const totalEstudiantes = Number(statsData.totalEstudiantes || 0);
  const tasaCumplimiento = totalPrestamos > 0
    ? ((totalCompletados / totalPrestamos) * 100).toFixed(1)
    : '0.0';

  const topMaterial = (statsData.topMateriales || [])[0];
  const topRiesgo = (statsData.topPerdidos || [])[0];

  return {
    resumen_ejecutivo: `Analisis generado sin Genkit: ${totalEstudiantes} estudiantes, ${totalPrestamos} prestamos, ${totalAdeudos} adeudos y cumplimiento de ${tasaCumplimiento}%.`,
    insights: [
      `Material mas solicitado: ${topMaterial ? `${topMaterial.material} (${topMaterial.cantidad})` : 'Sin datos'}.`,
      `Material de mayor riesgo: ${topRiesgo ? `${topRiesgo.material} (${topRiesgo.cantidad} casos)` : 'Sin datos'}.`,
      `Tasa de cumplimiento: ${tasaCumplimiento}%.`,
    ],
    predicciones: [
      'Si aumenta la demanda del material top, el riesgo de adeudo podria subir.',
      'Sin intervenciones, los adeudos tienden a concentrarse en pocos materiales.',
    ],
    recomendaciones: [
      'Ajustar stock de materiales mas solicitados.',
      'Refuerzo preventivo para devoluciones de materiales con mayor riesgo.',
      'Dar seguimiento semanal a estudiantes con adeudos recurrentes.',
    ],
    alertas: [
      ...(topRiesgo
        ? [{
          tipo: 'material_riesgo',
          mensaje: `${topRiesgo.material} concentra la mayor incidencia de adeudos.`,
          prioridad: Number(topRiesgo.cantidad || 0) > 5 ? 'alta' : 'media',
        }]
        : []),
      ...(totalAdeudos > 0
        ? [{
          tipo: 'adeudos_activos',
          mensaje: `Existen ${totalAdeudos} adeudos pendientes en el sistema.`,
          prioridad: totalAdeudos > 20 ? 'alta' : 'media',
        }]
        : []),
    ],
    tendencias: [
      'La base de datos se actualiza por cron cada pocos minutos.',
      'La relacion prestamos/completados permite medir eficiencia operativa.',
    ],
  };
}

async function buildFallbackChatResponse(prompt, student) {
  const lower = String(prompt || '').toLowerCase();
  const studentUid = String((student || {}).id || '').trim();

  if (studentUid && lower.includes('prestamo')) {
    const loansSnapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Prestamos')
      .where('estado', '==', 'activo')
      .get();
    return `Genkit esta deshabilitado en esta version. Tienes ${loansSnapshot.size} prestamos activos.`;
  }

  if (studentUid && (lower.includes('adeudo') || lower.includes('deuda'))) {
    const debtsSnapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Adeudos')
      .where('estado', '==', 'pendiente')
      .get();
    return `Genkit esta deshabilitado en esta version. Tienes ${debtsSnapshot.size} adeudos pendientes.`;
  }

  return 'Genkit ya no se usa en esta version. Puedes seguir usando el backend para catalogo, prestamos, adeudos, formularios, pagos y QR.';
}

async function handleOverdueLoansAutomation() {
  const now = Date.now();
  let processedLoans = 0;

  const studentsSnapshot = await db.collection('Estudiantes').get();

  for (const studentDoc of studentsSnapshot.docs) {
    const studentUid = studentDoc.id;
    const studentData = studentDoc.data() || {};
    const loansRef = db.collection('Estudiantes').doc(studentUid).collection('Prestamos');
    const activeLoans = await loansRef.where('estado', '==', 'activo').get();

    for (const loanDoc of activeLoans.docs) {
      const loanData = loanDoc.data() || {};
      const dueDate = toDate(loanData.fechaDevolucion);
      if (!dueDate || dueDate.getTime() > now) continue;

      const adeudoData = {
        cantidad: Number(loanData.cantidad || 1),
        codigo: generateDebtCode(studentData.grupo || 'SG'),
        estado: 'pendiente',
        fechaVencimiento: loanData.fechaDevolucion || admin.firestore.Timestamp.now(),
        grupo: studentData.grupo || '',
        moneda: 'MXN',
        nombreMaterial: loanData.nombreMaterial || '',
        precio_ajustado: Number(loanData.precio_total || loanData.precio_ajustado || 0),
        precio_unitario: Number(loanData.precio_unitario || 0),
        tipo: 'retraso',
        prestamoOriginal: loanDoc.id,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };

      const adeudoRef = db.collection('Estudiantes').doc(studentUid).collection('Adeudos').doc();
      const notificacionRef = db.collection('Estudiantes').doc(studentUid).collection('Notificaciones').doc();

      await db.runTransaction(async (transaction) => {
        transaction.set(adeudoRef, adeudoData);
        transaction.set(notificacionRef, {
          enviado: true,
          fechaEnvio: admin.firestore.FieldValue.serverTimestamp(),
          mensaje: `Se genero un adeudo por no devolver: ${loanData.nombreMaterial || 'material'}.`,
          link: '/dashboard/adeudos',
          tipo: 'nuevo_adeudo',
          leido: false,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        transaction.update(loanDoc.ref, { estado: 'vencido' });
      });

      if (studentData.correo && studentData.nombre) {
        await sendEmail({
          from: emailFrom('Notificaciones La Salle'),
          to: studentData.correo,
          subject: 'Notificacion de prestamo vencido',
          html: createOverdueLoanHtmlBody({
            studentName: studentData.nombre,
            materialName: loanData.nombreMaterial || 'Material',
            loanDate: toDate(loanData.fechaInicio) || new Date(),
            returnDate: toDate(loanData.fechaDevolucion) || new Date(),
          }),
        });
      }

      processedLoans += 1;
    }
  }

  return { processedLoans };
}

async function runCheckExpiredLoans() {
  const now = Date.now();
  let processedCount = 0;
  let batchesCommitted = 0;
  const errors = [];

  const studentsSnapshot = await db.collection('Estudiantes').get();
  for (const studentDoc of studentsSnapshot.docs) {
    const loansSnapshot = await studentDoc.ref
      .collection('Prestamos')
      .where('estado', '==', 'activo')
      .get();

    const expiredLoans = loansSnapshot.docs.filter((loanDoc) => {
      const dueDate = toDate((loanDoc.data() || {}).fechaDevolucion);
      return dueDate && dueDate.getTime() < now;
    });

    if (!expiredLoans.length) continue;

    const batch = db.batch();
    for (const loanDoc of expiredLoans) {
      const loanData = loanDoc.data() || {};
      batch.update(loanDoc.ref, {
        estado: 'expirado',
        fechaExpiracion: admin.firestore.Timestamp.now(),
      });

      batch.set(studentDoc.ref.collection('Notificaciones').doc(), {
        tipo: 'vencimiento',
        prestamoId: loanDoc.id,
        mensaje: `Tu prestamo de ${loanData.nombreMaterial || 'material'} ha vencido.`,
        enviado: true,
        fechaEnvio: admin.firestore.Timestamp.now(),
        canal: 'interno',
        leida: false,
      });

      processedCount += 1;
    }

    try {
      await batch.commit();
      batchesCommitted += 1;
    } catch (error) {
      errors.push(`Commit ${studentDoc.id}: ${error.message}`);
    }
  }

  return { processedCount, batchesCommitted, errors };
}

async function runSendReminders() {
  const now = Date.now();
  const twentyFourHoursAgo = now - 24 * 60 * 60 * 1000;
  const oneDayAhead = now + 24 * 60 * 60 * 1000;

  const stats = {
    adeudosCreados: 0,
    recordatoriosEnviados: 0,
    emailsEnviados: 0,
    prestamosAnalizados: 0,
    errors: [],
  };

  const studentsSnapshot = await db.collection('Estudiantes').get();
  for (const studentDoc of studentsSnapshot.docs) {
    const studentData = studentDoc.data() || {};
    const studentEmail = String(studentData.correo || '').trim();
    const loansRef = studentDoc.ref.collection('Prestamos');

    const expiredSnapshot = await loansRef.where('estado', '==', 'expirado').get();
    stats.prestamosAnalizados += expiredSnapshot.size;

    const expiredLoans = expiredSnapshot.docs.filter((doc) => {
      const loanData = doc.data() || {};
      const dueDate = toDate(loanData.fechaDevolucion);
      return dueDate && dueDate.getTime() < twentyFourHoursAgo;
    });

    for (const loanDoc of expiredLoans) {
      const loanData = loanDoc.data() || {};
      try {
        if (!loanData.nombreMaterial || loanData.cantidad === undefined || loanData.precio_unitario === undefined) {
          continue;
        }

        const existingAdeudo = await studentDoc.ref
          .collection('Adeudos')
          .where('prestamoOriginal', '==', loanDoc.id)
          .limit(1)
          .get();

        if (!existingAdeudo.empty) continue;

        const adeudoCodigo = generateDebtCode(loanData.grupo || 'XXX');
        const precioAjustado = Number(loanData.precio_total || (loanData.cantidad * loanData.precio_unitario) || 0);
        await studentDoc.ref.collection('Adeudos').add({
          codigo: adeudoCodigo,
          nombreMaterial: loanData.nombreMaterial,
          cantidad: Number(loanData.cantidad || 0),
          precio_unitario: Number(loanData.precio_unitario || 0),
          precio_ajustado: precioAjustado,
          moneda: 'MXN',
          estado: 'pendiente',
          tipo: 'vencimiento',
          fechaVencimiento: loanData.fechaDevolucion || admin.firestore.Timestamp.now(),
          grupo: loanData.grupo || '',
          prestamoOriginal: loanDoc.id,
          fechaCreacion: admin.firestore.Timestamp.now(),
        });

        await loanDoc.ref.delete();
        await studentDoc.ref.collection('Notificaciones').add({
          tipo: 'adeudo',
          prestamoId: loanDoc.id,
          mensaje: `Se genero un adeudo por ${loanData.nombreMaterial}.`,
          enviado: true,
          fechaEnvio: admin.firestore.Timestamp.now(),
          canal: 'interno',
          leida: false,
        });

        stats.adeudosCreados += 1;

        if (studentEmail && isValidEmail(studentEmail)) {
          const mailResult = await sendEmail({
            from: emailFrom('Notificaciones La Salle'),
            to: studentEmail,
            subject: `Adeudo generado - ${loanData.nombreMaterial}`,
            html: createDebtGeneratedHtml({
              studentName: studentData.nombre || 'Estudiante',
              materialName: loanData.nombreMaterial || 'Material',
              quantity: Number(loanData.cantidad || 0),
              amount: precioAjustado,
              debtCode: adeudoCodigo,
              dueDate: toDate(loanData.fechaDevolucion) || new Date(),
            }),
          });
          if (mailResult.success) stats.emailsEnviados += 1;
        }
      } catch (error) {
        stats.errors.push(`Adeudo ${loanDoc.id}: ${error.message}`);
      }
    }

    const activeSnapshot = await loansRef.where('estado', '==', 'activo').get();
    stats.prestamosAnalizados += activeSnapshot.size;

    const upcomingLoans = activeSnapshot.docs.filter((doc) => {
      const loanData = doc.data() || {};
      const dueDate = toDate(loanData.fechaDevolucion);
      if (!dueDate) return false;
      const dueMillis = dueDate.getTime();
      return dueMillis >= now && dueMillis <= oneDayAhead;
    });

    for (const loanDoc of upcomingLoans) {
      const loanData = loanDoc.data() || {};
      try {
        if (loanData.recordatorioEnviado) continue;

        await loanDoc.ref.update({
          recordatorioEnviado: true,
          fechaRecordatorio: admin.firestore.Timestamp.now(),
        });

        await studentDoc.ref.collection('Notificaciones').add({
          tipo: 'recordatorio',
          prestamoId: loanDoc.id,
          mensaje: `Tu prestamo de ${loanData.nombreMaterial || 'material'} vence pronto.`,
          enviado: true,
          fechaEnvio: admin.firestore.Timestamp.now(),
          canal: 'interno',
          leida: false,
        });

        stats.recordatoriosEnviados += 1;

        if (studentEmail && isValidEmail(studentEmail)) {
          const mailResult = await sendEmail({
            from: emailFrom('Notificaciones La Salle'),
            to: studentEmail,
            subject: `Recordatorio de devolucion - ${loanData.nombreMaterial || 'Prestamo'}`,
            html: createReminderHtml({
              studentName: studentData.nombre || 'Estudiante',
              materialName: loanData.nombreMaterial || 'Material',
              quantity: Number(loanData.cantidad || 0),
              returnDate: toDate(loanData.fechaDevolucion) || new Date(),
              code: loanData.codigo || loanDoc.id,
            }),
          });
          if (mailResult.success) stats.emailsEnviados += 1;
        }
      } catch (error) {
        stats.errors.push(`Recordatorio ${loanDoc.id}: ${error.message}`);
      }
    }
  }

  return stats;
}

async function runGenerateForms() {
  const stats = {
    formulariosCreados: 0,
    emailsEnviados: 0,
    adeudosAnalizados: 0,
    errors: [],
  };

  const studentsSnapshot = await db.collection('Estudiantes').get();
  for (const studentDoc of studentsSnapshot.docs) {
    const studentData = studentDoc.data() || {};
    const studentEmail = String(studentData.correo || '').trim();
    const studentUid = studentDoc.id;
    const adeudosRef = studentDoc.ref.collection('Adeudos');
    const formulariosRef = studentDoc.ref.collection('Formularios');

    const adeudosSnapshot = await adeudosRef
      .where('estado', '==', 'pendiente')
      .where('tipo', '==', 'vencimiento')
      .get();

    stats.adeudosAnalizados += adeudosSnapshot.size;
    for (const adeudoDoc of adeudosSnapshot.docs) {
      const adeudoData = adeudoDoc.data() || {};
      const adeudoId = adeudoDoc.id;
      const prestamoOriginal = adeudoData.prestamoOriginal || '';

      try {
        const existingForm = await formulariosRef
          .where('prestamoId', '==', prestamoOriginal)
          .where('adeudoId', '==', adeudoId)
          .limit(1)
          .get();

        if (!existingForm.empty) continue;

        const formId = `FORM-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
        const formUrl = `${APP_URL}/formularios/${formId}`;
        const pregunta = `No has devuelto "${adeudoData.nombreMaterial || 'material'}". Que sucedio?`;
        const opciones = ['Lo tengo pero no lo he devuelto', 'Lo rompi', 'Lo perdi'];

        const formData = {
          formId,
          prestamoId: prestamoOriginal,
          adeudoId,
          tipo: 'seguimiento',
          pregunta,
          opciones,
          respuesta: '',
          estado: 'pendiente',
          fechaCreacion: admin.firestore.Timestamp.now(),
          urlFormulario: formUrl,
        };

        const formDataGlobal = {
          ...formData,
          uid: studentUid,
          nombreEstudiante: studentData.nombre || '',
          correoEstudiante: studentEmail || '',
          nombreMaterial: adeudoData.nombreMaterial || '',
          cantidad: Number(adeudoData.cantidad || 0),
          codigoAdeudo: adeudoData.codigo || '',
          grupo: adeudoData.grupo || '',
          precio_ajustado: Number(adeudoData.precio_ajustado || 0),
        };

        const batch = db.batch();
        batch.set(formulariosRef.doc(formId), formData);
        batch.set(db.collection('FormulariosGlobal').doc(formId), formDataGlobal);
        batch.set(studentDoc.ref.collection('Notificaciones').doc(), {
          tipo: 'formulario',
          prestamoId: prestamoOriginal,
          adeudoId,
          mensaje: `Completa el formulario sobre tu adeudo de ${adeudoData.nombreMaterial || 'material'}.`,
          formUrl,
          enviado: true,
          fechaEnvio: admin.firestore.Timestamp.now(),
          canal: 'interno',
          leida: false,
        });
        await batch.commit();
        stats.formulariosCreados += 1;

        if (studentEmail && isValidEmail(studentEmail)) {
          const mailResult = await sendEmail({
            from: emailFrom('Notificaciones La Salle'),
            to: studentEmail,
            subject: `Formulario de seguimiento - ${adeudoData.nombreMaterial || 'Adeudo'}`,
            html: createFormRequestHtml({
              studentName: studentData.nombre || 'Estudiante',
              materialName: adeudoData.nombreMaterial || 'Material',
              quantity: Number(adeudoData.cantidad || 0),
              debtCode: adeudoData.codigo || '',
              question: pregunta,
              options: opciones,
              formUrl,
              qrImageUrl: generateQRCodeDataURL(formUrl),
            }),
          });
          if (mailResult.success) stats.emailsEnviados += 1;
        }
      } catch (error) {
        stats.errors.push(`Adeudo ${adeudoId}: ${error.message}`);
      }
    }
  }

  return stats;
}

async function collectStudentDataForStats() {
  const studentsSnapshot = await db.collection('Estudiantes').get();
  const allData = [];

  for (const studentDoc of studentsSnapshot.docs) {
    const uid = studentDoc.id;
    const studentData = studentDoc.data() || {};

    const [prestamosSnap, adeudosSnap, completadosSnap, pagadosSnap] = await Promise.all([
      db.collection('Estudiantes').doc(uid).collection('Prestamos').get(),
      db.collection('Estudiantes').doc(uid).collection('Adeudos').get(),
      db.collection('Estudiantes').doc(uid).collection('Completados').get(),
      db.collection('Estudiantes').doc(uid).collection('Pagados').get(),
    ]);

    allData.push({
      uid,
      nombre: studentData.nombre || '',
      grupo: studentData.grupo || '',
      prestamos: prestamosSnap.docs.filter((doc) => doc.id !== '_placeholder').map((doc) => doc.data() || {}),
      adeudos: adeudosSnap.docs.filter((doc) => doc.id !== '_placeholder').map((doc) => doc.data() || {}),
      completados: completadosSnap.docs.filter((doc) => doc.id !== '_placeholder').map((doc) => doc.data() || {}),
      pagados: pagadosSnap.docs.filter((doc) => doc.id !== '_placeholder').map((doc) => doc.data() || {}),
    });
  }

  return allData;
}

function calculateStatsFromData(data) {
  const materialCount = {};
  const materialPerdido = {};
  const studentScore = {};

  data.forEach((student) => {
    student.prestamos.forEach((prestamo) => {
      const key = prestamo.nombreMaterial || 'Sin nombre';
      materialCount[key] = (materialCount[key] || 0) + 1;
    });

    student.adeudos.forEach((adeudo) => {
      const key = adeudo.nombreMaterial || 'Sin nombre';
      if (!materialPerdido[key]) {
        materialPerdido[key] = { count: 0, tipo: adeudo.tipo || 'desconocido' };
      }
      materialPerdido[key].count += 1;
    });

    const completados = student.completados.length;
    const adeudos = student.adeudos.length;
    const score = completados - (adeudos * 2);
    studentScore[student.uid] = {
      nombre: student.nombre,
      grupo: student.grupo,
      completados,
      adeudos,
      score,
    };
  });

  const topMateriales = Object.entries(materialCount)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 5)
    .map(([material, cantidad]) => ({ material, cantidad }));

  const topPerdidos = Object.entries(materialPerdido)
    .sort(([, a], [, b]) => b.count - a.count)
    .slice(0, 5)
    .map(([material, value]) => ({ material, cantidad: value.count, tipo: value.tipo }));

  const topEstudiantes = Object.values(studentScore)
    .sort((a, b) => b.score - a.score)
    .slice(0, 5);

  const peoresEstudiantes = Object.values(studentScore)
    .sort((a, b) => a.score - b.score)
    .slice(0, 5);

  return {
    topMateriales,
    topPerdidos,
    topEstudiantes,
    peoresEstudiantes,
    totalPrestamos: data.reduce((sum, item) => sum + item.prestamos.length, 0),
    totalAdeudos: data.reduce((sum, item) => sum + item.adeudos.length, 0),
    totalCompletados: data.reduce((sum, item) => sum + item.completados.length, 0),
    totalEstudiantes: data.length,
  };
}

function buildContextForCharts(stats) {
  const tasaCumplimiento = stats.totalPrestamos > 0
    ? ((stats.totalCompletados / stats.totalPrestamos) * 100).toFixed(1)
    : '0';

  return {
    resumen_ejecutivo: `Dashboard con ${stats.totalEstudiantes} estudiantes activos, ${stats.totalPrestamos} prestamos, ${stats.totalCompletados} completados y ${stats.totalAdeudos} adeudos.`,
    insights: [
      `Material mas solicitado: ${stats.topMateriales[0]?.material || 'N/A'} (${stats.topMateriales[0]?.cantidad || 0}).`,
      `Materiales con mayor incidencia: ${stats.topPerdidos.length}.`,
      `Tasa de cumplimiento general: ${tasaCumplimiento}%.`,
    ],
    predicciones: [
      'Los materiales con mayor adeudo requieren monitoreo de stock y devolucion.',
      'El comportamiento se actualiza automaticamente con los cron jobs.',
    ],
    recomendaciones: [
      'Monitorear materiales con mayor tasa de perdida.',
      'Contactar estudiantes con adeudos recurrentes.',
      'Refrescar politicas de devolucion para grupos con mayor incidencia.',
    ],
    alertas: stats.topPerdidos.slice(0, 3).map((item) => ({
      tipo: 'material_riesgo',
      mensaje: `${item.material} presenta ${item.cantidad} casos de ${item.tipo}.`,
      prioridad: item.cantidad > 5 ? 'alta' : 'media',
    })),
    tendencias: [
      'El top 5 de materiales cambia segun la temporada academica.',
      'El ratio de adeudos permite identificar semanas criticas.',
    ],
  };
}

async function runEstadisticasBasicas() {
  const allData = await collectStudentDataForStats();
  const stats = calculateStatsFromData(allData);
  const context = buildContextForCharts(stats);

  const reporteRef = db.collection('Estadisticas').doc('reporte_actual');
  const reporteSnap = await reporteRef.get();
  const existingData = reporteSnap.exists ? reporteSnap.data() || {} : {};

  const payload = {
    ...stats,
    contextoGraficas: context,
    analisisIA: existingData.analisisIA || context,
    ultimaActualizacion: admin.firestore.FieldValue.serverTimestamp(),
    version: Date.now(),
  };

  if (existingData.ultimaActualizacionIA) {
    payload.ultimaActualizacionIA = existingData.ultimaActualizacionIA;
  }

  await reporteRef.set(payload);
  return stats;
}

app.get('/auth/microsoft/start', (req, res) => {
  if (!AZURE_TENANT_ID || !AZURE_CLIENT_ID || !AZURE_CLIENT_SECRET) {
    return res.status(500).json({
      success: false,
      message: 'Azure OAuth no esta configurado. Revisa AZURE_TENANT_ID, AZURE_CLIENT_ID y AZURE_CLIENT_SECRET.',
    });
  }

  const rawRedirect = String(req.query.redirect || DEFAULT_STUDENT_REDIRECT).trim();
  const redirectTarget = rawRedirect.startsWith('/') ? rawRedirect : DEFAULT_STUDENT_REDIRECT;

  const state = randomHex(24);
  const nonce = randomHex(24);

  setCookie(res, AZURE_STATE_COOKIE, state, 10 * 60 * 1000);
  setCookie(res, AZURE_NONCE_COOKIE, nonce, 10 * 60 * 1000);
  setCookie(res, AZURE_REDIRECT_COOKIE, redirectTarget, 10 * 60 * 1000);

  const params = new URLSearchParams({
    client_id: AZURE_CLIENT_ID,
    response_type: 'code',
    redirect_uri: AZURE_REDIRECT_URI,
    response_mode: 'query',
    scope: AZURE_SCOPE,
    state,
    nonce,
    prompt: 'select_account',
  });

  const authorizeUrl =
    `https://login.microsoftonline.com/${encodeURIComponent(AZURE_TENANT_ID)}/oauth2/v2.0/authorize?` +
    params.toString();

  return res.redirect(authorizeUrl);
});

app.get('/auth/microsoft/callback', async (req, res) => {
  const errorFromAzure = String(req.query.error || '').trim();
  const errorDescription = String(req.query.error_description || '').trim();
  const redirectCookie =
    req.cookies?.[AZURE_REDIRECT_COOKIE] ||
    getCookieFromHeader(req, AZURE_REDIRECT_COOKIE);
  const redirectTarget = String(redirectCookie || DEFAULT_STUDENT_REDIRECT).startsWith('/')
    ? String(redirectCookie || DEFAULT_STUDENT_REDIRECT)
    : DEFAULT_STUDENT_REDIRECT;

  const failWithRedirect = (message) => {
    clearAzureOauthCookies(res);
    return res.redirect(getLoginRedirectWithError(message));
  };

  if (!AZURE_TENANT_ID || !AZURE_CLIENT_ID || !AZURE_CLIENT_SECRET) {
    return failWithRedirect('Azure OAuth no esta configurado en el backend.');
  }

  if (errorFromAzure) {
    return failWithRedirect(errorDescription || errorFromAzure);
  }

  const code = String(req.query.code || '').trim();
  const state = String(req.query.state || '').trim();
  const stateCookie = String(
    req.cookies?.[AZURE_STATE_COOKIE] ||
    getCookieFromHeader(req, AZURE_STATE_COOKIE) ||
    ''
  ).trim();
  const nonceCookie = String(
    req.cookies?.[AZURE_NONCE_COOKIE] ||
    getCookieFromHeader(req, AZURE_NONCE_COOKIE) ||
    ''
  ).trim();

  if (!code || !state) {
    return failWithRedirect('La respuesta de Microsoft no incluyo codigo de autorizacion.');
  }

  if (!stateCookie || state !== stateCookie) {
    return failWithRedirect('Estado OAuth invalido. Intenta de nuevo.');
  }

  try {
    const tokenEndpoint =
      `https://login.microsoftonline.com/${encodeURIComponent(AZURE_TENANT_ID)}/oauth2/v2.0/token`;

    const tokenPayload = new URLSearchParams({
      client_id: AZURE_CLIENT_ID,
      client_secret: AZURE_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code,
      redirect_uri: AZURE_REDIRECT_URI,
      scope: AZURE_SCOPE,
    });

    const tokenResponse = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: tokenPayload.toString(),
    });

    const tokenData = await tokenResponse.json().catch(() => ({}));
    if (!tokenResponse.ok) {
      const errorMessage =
        tokenData.error_description ||
        tokenData.error ||
        'No se pudo completar el intercambio de token con Microsoft.';
      return failWithRedirect(errorMessage);
    }

    const claims = decodeJwtPayload(tokenData.id_token);
    if (!claims) {
      return failWithRedirect('Token de identidad invalido.');
    }

    if (nonceCookie && String(claims.nonce || '') !== nonceCookie) {
      return failWithRedirect('Nonce OAuth invalido. Intenta de nuevo.');
    }

    const email = String(
      claims.preferred_username ||
      claims.email ||
      claims.upn ||
      ''
    ).trim().toLowerCase();

    if (!isValidEmail(email)) {
      return failWithRedirect('Microsoft no devolvio un correo valido para esta cuenta.');
    }

    if (!isAllowedStudentEmail(email)) {
      return failWithRedirect('Tu correo no tiene permisos para ingresar como estudiante.');
    }

    const name = String(claims.name || email.split('@')[0] || 'Estudiante').trim();
    const uid = String(claims.oid || claims.sub || createDeterministicStudentUid(email)).trim();
    const grupo = extractGrupoFromEmail(email) || '';

    await createOrUpdateStudentServer({
      id: uid,
      name,
      email,
      grupo,
      rol: 'estudiante',
      carrera: 'turismo',
      image: '',
    });

    const sessionData = {
      id: uid,
      name,
      email,
      grupo,
      provider: 'azure',
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 24 * 60 * 60 * 1000,
    };

    setCookie(
      res,
      STUDENT_SESSION_COOKIE,
      encodeSessionCookie(sessionData),
      5 * 24 * 60 * 60 * 1000
    );

    clearAzureOauthCookies(res);
    return res.redirect(redirectTarget);
  } catch (error) {
    console.error('[AZURE_OAUTH] Error en callback:', error.message);
    return failWithRedirect('No se pudo completar el inicio de sesion con Microsoft.');
  }
});

app.get('/api/student/session', asyncHandler(async (req, res) => {
  const session = getStudentSessionFromRequest(req);
  if (!session.ok) {
    if (session.status === 401 || session.status === 403) {
      clearCookie(res, STUDENT_SESSION_COOKIE);
    }
    return res.status(session.status).json({
      success: false,
      message: session.message,
    });
  }

  const studentDoc = await db.collection('Estudiantes').doc(session.claims.id).get();
  if (!studentDoc.exists) {
    clearCookie(res, STUDENT_SESSION_COOKIE);
    return res.status(404).json({
      success: false,
      message: 'La sesion existe, pero el estudiante no fue encontrado.',
    });
  }

  const studentData = studentDoc.data() || {};
  const payload = {
    id: session.claims.id,
    name: String(studentData.nombre || session.claims.name || 'Estudiante'),
    email: String(studentData.correo || session.claims.email || '').toLowerCase(),
    grupo: String(studentData.grupo || session.claims.grupo || ''),
    provider: session.claims.provider || 'azure',
  };

  return res.status(200).json({
    success: true,
    student: payload,
  });
}));

app.post('/api/student/session/logout', (_req, res) => {
  clearCookie(res, STUDENT_SESSION_COOKIE);
  return res.status(200).json({
    success: true,
    message: 'Sesion de estudiante cerrada.',
  });
});

app.get('/', (_req, res) => {
  res.status(200).json({
    ok: true,
    service: 'LaSalleGestiona backend',
    timestamp: new Date().toISOString(),
  });
});

app.get('/health', (_req, res) => {
  res.status(200).json({
    ok: true,
    firebase: true,
    realtimeDb: Boolean(rtdb),
    emailConfigured: Boolean(getEmailTransporter()),
    azureOauthConfigured: Boolean(AZURE_TENANT_ID && AZURE_CLIENT_ID && AZURE_CLIENT_SECRET),
  });
});

app.get(
  ['/api/catalogo', '/api/materiales'],
  asyncHandler(async (_req, res) => {
    if (!rtdb) {
      return res.status(500).json({
        success: false,
        message: 'Realtime Database no esta configurada.',
      });
    }

    const snapshot = await rtdb.ref('materiales').once('value');
    const raw = snapshot.val() || {};

    const materiales = Object.keys(raw).map((id) => {
      const item = raw[id] || {};
      return {
        id,
        ...item,
        stock: Number(item.cantidad || 0),
      };
    });

    return res.status(200).json({ success: true, materiales });
  })
);

app.post(
  '/api/upsert',
  asyncHandler(async (req, res) => {
    const user = req.body || {};

    if (!user.id || !user.email) {
      return res.status(400).json({
        error: 'Faltan datos del usuario (id o email).',
      });
    }

    await createOrUpdateStudentServer(user);
    return res.status(200).json({ ok: true, message: 'Usuario creado/actualizado.' });
  })
);

app.get(
  '/api/estudiantes/buscar',
  asyncHandler(async (req, res) => {
    const email = String(req.query.email || '').trim().toLowerCase();
    if (!email) {
      return res.status(400).json({
        found: false,
        message: 'El correo es requerido.',
      });
    }

    const student = await findStudentByEmail(email);
    if (!student) {
      return res.status(404).json({
        found: false,
        message: 'No existe un estudiante con ese correo.',
      });
    }

    return res.status(200).json({
      found: true,
      uid: student.id,
      student: student.data || {},
    });
  })
);

app.get(
  '/api/prestamos',
  asyncHandler(async (req, res) => {
    const studentUid = String(req.query.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ message: 'El ID del estudiante es requerido.' });
    }

    const loansSnapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Prestamos')
      .where('estado', '==', 'activo')
      .get();

    const loans = loansSnapshot.docs.map((doc) => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        fechaInicio: toISO(data.fechaInicio),
        fechaDevolucion: toISO(data.fechaDevolucion),
      };
    });

    return res.status(200).json(loans);
  })
);

app.post(
  '/api/prestamos',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const studentUid = String(body.studentUid || '').trim();
    const materialId = String(body.materialId || '').trim();
    const materialNombre = String(body.materialNombre || '').trim();
    const cantidad = Number(body.cantidad || 0);
    const fechaDevolucion = body.fechaDevolucion;
    const grupo = String(body.grupo || '').trim().toUpperCase();
    const precioUnitarioFront = Number(body.precio_unitario || 0);
    const precioAjustadoFront = Number(body.precio_ajustado || 0);

    if (!studentUid || !materialId || !materialNombre || !cantidad || !fechaDevolucion || !grupo) {
      return res.status(400).json({ message: 'Faltan datos requeridos.' });
    }

    if (!rtdb) {
      return res.status(500).json({ message: 'Realtime Database no esta configurada.' });
    }

    const materialRef = rtdb.ref(`materiales/${materialId}`);
    const materialSnapshot = await materialRef.once('value');
    if (!materialSnapshot.exists()) {
      return res.status(404).json({ message: `El material con ID ${materialId} no existe.` });
    }

    const materialData = materialSnapshot.val() || {};
    const precioUnitario = precioUnitarioFront > 0
      ? precioUnitarioFront
      : Number(materialData.precio_unitario || materialData.precio || 0);
    const precioAjustado = precioAjustadoFront > 0
      ? precioAjustadoFront
      : Number(materialData.precio_ajustado || precioUnitario);

    const loanCode = generateLoanCode(grupo);
    const qrToken = randomHex(32);
    const fechaDevolucionTs = toTimestamp(fechaDevolucion) || admin.firestore.Timestamp.now();

    const prestamoRef = db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Prestamos')
      .doc(loanCode);

    const qrRef = db.collection('qrs').doc(loanCode);

    await db.runTransaction(async (transaction) => {
      transaction.set(prestamoRef, {
        studentUid,
        codigo: loanCode,
        materialId,
        nombreMaterial: materialNombre,
        cantidad,
        precio_unitario: precioUnitario,
        precio_ajustado: precioAjustado,
        precio_total: precioAjustado * cantidad,
        fechaSolicitud: admin.firestore.FieldValue.serverTimestamp(),
        fechaDevolucion: fechaDevolucionTs,
        estado: 'pendiente_activacion',
        grupo,
        qrToken,
      });

      transaction.set(qrRef, {
        status: 'pendiente',
        operationId: loanCode,
        operationType: 'prestamos',
        studentUid,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        validatedAt: null,
        validatedBy: null,
      });
    });

    return res.status(201).json({
      message: 'Solicitud de prestamo creada.',
      loanCode,
      qrToken,
    });
  })
);

app.post(
  '/api/prestamos/activate',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const codigo = String((req.body || {}).codigo || '').trim();
    if (!codigo) {
      return res.status(400).json({ message: 'El codigo QR es requerido.' });
    }

    if (!rtdb) {
      return res.status(500).json({ message: 'Realtime Database no esta configurada.' });
    }

    const qrDocRef = db.collection('qrs').doc(codigo);
    const qrDoc = await qrDocRef.get();

    if (!qrDoc.exists) {
      return res.status(404).json({ message: `Codigo QR "${codigo}" no encontrado.` });
    }

    const qrData = qrDoc.data() || {};
    if (qrData.status !== 'pendiente') {
      return res.status(409).json({ message: `Este QR ya fue procesado. Estado: ${qrData.status}.` });
    }

    if (qrData.operationType !== 'prestamos') {
      return res.status(400).json({ message: 'Este QR no corresponde a prestamos.' });
    }

    const prestamoRef = db
      .collection('Estudiantes')
      .doc(qrData.studentUid)
      .collection('Prestamos')
      .doc(qrData.operationId);

    const prestamoDoc = await prestamoRef.get();
    if (!prestamoDoc.exists) {
      return res.status(500).json({ message: 'El prestamo asociado al QR no existe.' });
    }

    const prestamoData = prestamoDoc.data() || {};
    const materialId = prestamoData.materialId;
    const cantidad = Number(prestamoData.cantidad || 0);

    if (!materialId || !cantidad) {
      return res.status(500).json({ message: 'El prestamo no tiene materialId o cantidad validos.' });
    }

    const materialRef = rtdb.ref(`materiales/${materialId}`);
    const transactionResult = await materialRef.transaction((currentData) => {
      if (!currentData) return;

      const currentStock = Number(currentData.cantidad || 0);
      if (currentStock < cantidad) return;

      return {
        ...currentData,
        cantidad: currentStock - cantidad,
      };
    });

    if (!transactionResult.committed) {
      const currentStockSnapshot = await materialRef.once('value');
      const currentStock = Number((currentStockSnapshot.val() || {}).cantidad || 0);
      return res.status(409).json({
        message: `Stock insuficiente. Disponible: ${currentStock}, solicitado: ${cantidad}.`,
      });
    }

    await db.runTransaction(async (transaction) => {
      transaction.update(prestamoRef, {
        estado: 'activo',
        fechaInicio: admin.firestore.FieldValue.serverTimestamp(),
      });
      transaction.update(qrDocRef, {
        status: 'validado',
        validatedAt: admin.firestore.FieldValue.serverTimestamp(),
        validatedBy: req.adminClaims.uid,
      });
    });

    return res.status(200).json({ message: 'Prestamo activado con exito.' });
  })
);

app.get(
  '/api/adeudos',
  asyncHandler(async (req, res) => {
    const studentUid = String(req.query.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ message: 'El ID del estudiante es requerido.' });
    }

    const snapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Adeudos')
      .where('estado', '==', 'pendiente')
      .get();

    const adeudos = snapshot.docs.map((doc) => {
      const data = doc.data() || {};
      const cantidad = Number(data.cantidad || 1);
      const precioUnitario = Number(data.precio_unitario || 0);
      const precioAjustado = Number(data.precio_ajustado || precioUnitario);

      return {
        id: doc.id,
        codigo: data.codigo || '',
        nombreMaterial: data.nombreMaterial || 'Sin nombre',
        cantidad,
        precio_unitario: precioUnitario,
        precio_ajustado: precioAjustado,
        moneda: data.moneda || 'MXN',
        estado: data.estado || 'pendiente',
        tipo: data.tipo || 'vencimiento',
        fechaVencimiento: toISO(data.fechaVencimiento),
        grupo: data.grupo || '',
        prestamoOriginal: data.prestamoOriginal || null,
      };
    });

    return res.status(200).json(adeudos);
  })
);

app.get(
  '/api/adeudos/:adeudoId',
  asyncHandler(async (req, res) => {
    const adeudoId = String(req.params.adeudoId || '').trim();
    const uid = String(req.query.uid || '').trim();

    if (!uid) {
      return res.status(400).json({ success: false, message: 'UID requerido.' });
    }

    const adeudoDoc = await db
      .collection('Estudiantes')
      .doc(uid)
      .collection('Adeudos')
      .doc(adeudoId)
      .get();

    if (!adeudoDoc.exists) {
      return res.status(404).json({ success: false, message: 'Adeudo no encontrado.' });
    }

    return res.status(200).json({ success: true, adeudo: adeudoDoc.data() });
  })
);

app.get(
  '/api/pagados',
  asyncHandler(async (req, res) => {
    const studentUid = String(req.query.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ message: 'El ID del estudiante es requerido.' });
    }

    const snapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Pagados')
      .get();

    const pagados = snapshot.docs
      .filter((doc) => doc.id !== '_placeholder')
      .map((doc) => {
        const data = doc.data() || {};
        return {
          id: doc.id,
          nombreMaterial: data.nombreMaterial || 'Material desconocido',
          precio_total: Number(data.precio || data.precio_total || 0),
          fechaVencimiento: toISO(data.fechaVencimiento) || new Date().toISOString(),
          fechaPago: toISO(data.fechaPago) || new Date().toISOString(),
        };
      })
      .sort((a, b) => new Date(b.fechaPago).getTime() - new Date(a.fechaPago).getTime());

    return res.status(200).json(pagados);
  })
);

app.get(
  '/api/completados',
  asyncHandler(async (req, res) => {
    const studentUid = String(req.query.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ message: 'El ID del estudiante es requerido.' });
    }

    const snapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Completados')
      .get();

    const completados = snapshot.docs
      .filter((doc) => doc.id !== '_placeholder')
      .map((doc) => {
        const data = doc.data() || {};
        return {
          id: doc.id,
          ...data,
          fechaInicio: toISO(data.fechaInicio),
          fechaDevolucion: toISO(data.fechaDevolucion || data.fechaDevolucionReal),
        };
      })
      .sort((a, b) => {
        const aDate = new Date(a.fechaDevolucion || 0).getTime();
        const bDate = new Date(b.fechaDevolucion || 0).getTime();
        return bDate - aDate;
      });

    return res.status(200).json(completados);
  })
);

app.post(
  '/api/procesar-pago',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const paymentId = String(body.paymentId || '').trim();
    const adeudoId = String(body.adeudoId || '').trim();
    const uid = String(body.uid || '').trim();
    const monto = Number(body.monto || 0);
    const metodoPago = String(body.metodoPago || '').trim();
    const cardData = body.cardData || null;

    if (!paymentId || !adeudoId || !uid || monto <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Datos incompletos o monto invalido.',
      });
    }

    const studentRef = db.collection('Estudiantes').doc(uid);
    const adeudoRef = studentRef.collection('Adeudos').doc(adeudoId);

    const [adeudoDoc, studentDoc] = await Promise.all([adeudoRef.get(), studentRef.get()]);
    if (!adeudoDoc.exists || !studentDoc.exists) {
      return res.status(404).json({
        success: false,
        message: 'Adeudo o estudiante no encontrado.',
      });
    }

    const adeudoData = adeudoDoc.data() || {};
    const studentData = studentDoc.data() || {};

    await delay(500);

    const transaccionId = `TXN-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const codigoPago = generatePaymentCode(adeudoData.grupo || 'XXX');

    const pagoData = {
      codigoPago,
      nombreMaterial: adeudoData.nombreMaterial || '',
      precio: monto,
      metodo: 'en linea',
      estado: 'pagado',
      fechaPago: admin.firestore.Timestamp.now(),
      adeudoOriginal: adeudoId,
      grupo: adeudoData.grupo || '',
      transaccionId,
      paymentId,
      metodoPagoDetalle: metodoPago,
      ultimosCuatroDigitos: cardData ? String(cardData.lastFour || '') : '',
    };

    const batch = db.batch();
    batch.update(adeudoRef, {
      estado: 'pagado',
      fechaPago: admin.firestore.Timestamp.now(),
      transaccionId,
      codigoPago,
    });

    const pagadoRef = studentRef.collection('Pagados').doc();
    batch.set(pagadoRef, pagoData);

    const notificationRef = studentRef.collection('Notificaciones').doc();
    batch.set(notificationRef, {
      tipo: 'pago',
      adeudoId,
      mensaje: `Pago exitoso de ${adeudoData.nombreMaterial || 'material'}.`,
      enviado: true,
      fechaEnvio: admin.firestore.Timestamp.now(),
      canal: 'interno',
      leida: false,
    });

    await batch.commit();

    if (studentData.correo) {
      await sendEmail({
        from: emailFrom('Notificaciones La Salle'),
        to: studentData.correo,
        subject: `Pago exitoso - ${adeudoData.nombreMaterial || 'Adeudo'}`,
        html: createPaymentSuccessHtml({
          studentName: studentData.nombre || 'Estudiante',
          materialName: adeudoData.nombreMaterial || 'Material',
          amount: monto,
          paymentCode: codigoPago,
          transactionId: transaccionId,
        }),
      });
    }

    return res.status(200).json({
      success: true,
      message: 'Pago procesado exitosamente.',
      transaccionId,
      codigoPago,
    });
  })
);

app.get(
  '/api/qr-center',
  asyncHandler(async (req, res) => {
    let studentUid = String(req.query.studentUid || '').trim();
    const studentEmail = String(req.query.email || req.headers['x-student-email'] || '').trim();

    if (!studentUid && studentEmail) {
      const studentByEmail = await findStudentByEmail(studentEmail);
      if (studentByEmail) {
        studentUid = studentByEmail.id;
      }
    }

    if (!studentUid) {
      return res.status(400).json({
        message: 'Se requiere studentUid o email para obtener el centro QR.',
      });
    }

    const studentRef = db.collection('Estudiantes').doc(studentUid);
    const studentDoc = await studentRef.get();
    if (!studentDoc.exists) {
      return res.status(404).json({ message: 'Estudiante no encontrado.' });
    }

    const [prestamosSnapshot, adeudosSnapshot] = await Promise.all([
      studentRef.collection('Prestamos').get(),
      studentRef.collection('Adeudos').get(),
    ]);

    const qrCenter = {
      activacion: [],
      devolucion: [],
      devolucionAdeudo: [],
      pago: [],
    };

    for (const doc of prestamosSnapshot.docs) {
      if (doc.id === '_placeholder') continue;
      const data = doc.data() || {};
      const estado = data.estado || '';

      if (estado === 'pendiente' || estado === 'pendiente_activacion') {
        qrCenter.activacion.push({
          id: doc.id,
          codigo: data.codigo || '',
          tipo: 'activacion',
          nombreMaterial: data.nombreMaterial || '',
          cantidad: Number(data.cantidad || 0),
          estado,
          fechaCreacion: toISO(data.fechaCreacion || data.fechaSolicitud),
          fechaLimite: toISO(data.fechaDevolucion),
          qrToken: data.codigo || doc.id,
          grupo: data.grupo || '',
        });
      }

      if (estado === 'activo' && data.qrToken) {
        qrCenter.devolucion.push({
          id: doc.id,
          codigo: data.codigo || '',
          tipo: 'devolucion',
          nombreMaterial: data.nombreMaterial || '',
          cantidad: Number(data.cantidad || 0),
          estado,
          fechaCreacion: toISO(data.fechaInicio || data.fechaSolicitud),
          fechaLimite: toISO(data.fechaDevolucion),
          qrToken: data.qrToken,
          grupo: data.grupo || '',
        });
      }
    }

    for (const doc of adeudosSnapshot.docs) {
      if (doc.id === '_placeholder') continue;
      const data = doc.data() || {};
      const estado = data.estado || '';
      if (estado !== 'pendiente') continue;

      if (data.tokenDevolucion && (data.tipo === 'vencimiento' || data.tipo === 'retraso')) {
        qrCenter.devolucionAdeudo.push({
          id: doc.id,
          codigo: data.codigo || '',
          tipo: 'devolucion_adeudo',
          nombreMaterial: data.nombreMaterial || '',
          cantidad: Number(data.cantidad || 0),
          estado,
          fechaCreacion: toISO(data.fechaCreacion || data.createdAt),
          qrToken: data.tokenDevolucion,
          grupo: data.grupo || '',
        });
      }

      if (data.tokenPago) {
        qrCenter.pago.push({
          id: doc.id,
          codigo: data.codigo || '',
          tipo: 'pago',
          nombreMaterial: data.nombreMaterial || '',
          cantidad: Number(data.cantidad || 0),
          estado,
          fechaCreacion: toISO(data.fechaCreacion || data.createdAt),
          monto: Number(data.precio_ajustado || data.precio_unitario || 0),
          qrToken: data.tokenPago,
          grupo: data.grupo || '',
        });
      }
    }

    const totales = {
      activacion: qrCenter.activacion.length,
      devolucion: qrCenter.devolucion.length,
      devolucionAdeudo: qrCenter.devolucionAdeudo.length,
      pago: qrCenter.pago.length,
      total:
        qrCenter.activacion.length
        + qrCenter.devolucion.length
        + qrCenter.devolucionAdeudo.length
        + qrCenter.pago.length,
    };

    return res.status(200).json({ ...qrCenter, totales });
  })
);

app.get(
  '/api/chatbot/check-overdue',
  asyncHandler(async (req, res) => {
    const studentUid = String(req.query.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ message: 'El ID del estudiante es requerido.' });
    }

    const loansSnapshot = await db
      .collection('Estudiantes')
      .doc(studentUid)
      .collection('Prestamos')
      .where('estado', '==', 'activo')
      .get();

    if (loansSnapshot.empty) {
      return res.status(200).json({ overdueLoan: null });
    }

    const now = Date.now();
    const overdueLoanDoc = loansSnapshot.docs.find((doc) => {
      const loanData = doc.data() || {};
      const dueDate = toDate(loanData.fechaDevolucion);
      return dueDate && dueDate.getTime() < now;
    });

    if (!overdueLoanDoc) {
      return res.status(200).json({ overdueLoan: null });
    }

    const loanData = overdueLoanDoc.data() || {};
    return res.status(200).json({
      overdueLoan: {
        id: overdueLoanDoc.id,
        ...loanData,
        fechaInicio: toISO(loanData.fechaInicio),
        fechaDevolucion: toISO(loanData.fechaDevolucion),
      },
    });
  })
);

app.post(
  '/api/chatbot/create-debt',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const studentUid = String(body.studentUid || '').trim();
    const loanId = String(body.loanId || '').trim();
    const reason = String(body.reason || '').trim();
    const loanDetails = body.loanDetails || {};

    if (!studentUid || !loanId || !reason || !loanDetails) {
      return res.status(400).json({ message: 'Faltan datos para crear el adeudo.' });
    }

    const studentRef = db.collection('Estudiantes').doc(studentUid);
    const loanRef = studentRef.collection('Prestamos').doc(loanId);
    const debtRef = studentRef.collection('Adeudos').doc(loanId);

    let precioAjustado = Number(loanDetails.precioUnitario || 0) * Number(loanDetails.cantidad || 0);
    let justificacion = 'Devolucion tardia.';
    let tipo = 'vencimiento';

    if (reason === 'broken') {
      precioAjustado *= 1.2;
      justificacion = 'Material danado.';
      tipo = 'rotura';
    } else if (reason === 'lost') {
      precioAjustado *= 1.5;
      justificacion = 'Material perdido.';
      tipo = 'perdida';
    }

    const newDebt = {
      nombreMaterial: loanDetails.nombreMaterial || '',
      cantidad: Number(loanDetails.cantidad || 1),
      precio_unitario: Number(loanDetails.precioUnitario || 0),
      precio_ajustado: Number(precioAjustado.toFixed(2)),
      fechaVencimiento: toTimestamp(loanDetails.fechaDevolucion) || admin.firestore.Timestamp.now(),
      fechaCreacion: admin.firestore.FieldValue.serverTimestamp(),
      estado: 'pendiente',
      justificacion,
      tipo,
      prestamoOriginal: loanId,
    };

    await db.runTransaction(async (transaction) => {
      const loanDoc = await transaction.get(loanRef);
      if (!loanDoc.exists) {
        throw new Error('El prestamo ya no existe o ya fue procesado.');
      }
      transaction.delete(loanRef);
      transaction.set(debtRef, newDebt);
    });

    return res.status(201).json({
      message: 'Adeudo creado exitosamente.',
      debt: { ...newDebt, id: debtRef.id },
    });
  })
);

app.get(
  '/api/formularios/:formId',
  asyncHandler(async (req, res) => {
    const formId = String(req.params.formId || '').trim();
    const formDoc = await db.collection('FormulariosGlobal').doc(formId).get();

    if (!formDoc.exists) {
      return res.status(404).json({ success: false, message: 'Formulario no encontrado.' });
    }

    return res.status(200).json({ success: true, formulario: formDoc.data() });
  })
);

app.post(
  '/api/formularios/:formId/responder',
  asyncHandler(async (req, res) => {
    const formId = String(req.params.formId || '').trim();
    const body = req.body || {};
    const respuesta = String(body.respuesta || '').trim();
    const metodoPago = String(body.metodoPago || '').trim();
    const adeudoId = String(body.adeudoId || '').trim();
    const uid = String(body.uid || '').trim();
    const correoEstudiante = String(body.correoEstudiante || '').trim();
    const nombreEstudiante = String(body.nombreEstudiante || '').trim();
    const nombreMaterial = String(body.nombreMaterial || '').trim();
    const cantidad = Number(body.cantidad || 0);
    const codigoAdeudo = String(body.codigoAdeudo || '').trim();
    const precioAjustado = Number(body.precio_ajustado || 0);

    if (!respuesta || !adeudoId || !uid) {
      return res.status(400).json({ success: false, message: 'Datos incompletos.' });
    }

    const studentRef = db.collection('Estudiantes').doc(uid);
    const adeudoRef = studentRef.collection('Adeudos').doc(adeudoId);
    const globalFormRef = db.collection('FormulariosGlobal').doc(formId);
    const studentFormRef = studentRef.collection('Formularios').doc(formId);

    const formUpdate = {
      respuesta,
      estado: 'completado',
      fechaRespuesta: admin.firestore.Timestamp.now(),
    };

    const montoFormateado = precioAjustado.toFixed(2);
    const baseUrl = APP_URL;

    if (respuesta === 'Lo tengo pero no lo he devuelto') {
      const devolucionToken = randomHex(32);
      const qrDevolucionUrl = `${baseUrl}/scan-devolucion-material/${devolucionToken}`;

      const batch = db.batch();
      batch.update(globalFormRef, formUpdate);
      batch.update(studentFormRef, formUpdate);
      batch.update(adeudoRef, {
        tokenDevolucion: devolucionToken,
        qrDevolucionUrl,
        respuestaFormulario: respuesta,
        fechaRespuestaFormulario: admin.firestore.Timestamp.now(),
      });
      await batch.commit();

      if (correoEstudiante) {
        await sendEmail({
          from: emailFrom('Notificaciones La Salle'),
          to: correoEstudiante,
          subject: `Codigo QR de devolucion - ${nombreMaterial || 'Material'}`,
          html: createFormReturnQrHtml({
            nombreEstudiante,
            nombreMaterial,
            cantidad,
            codigoAdeudo,
            qrUrl: qrDevolucionUrl,
          }),
        });
      }

      return res.status(200).json({
        success: true,
        message: 'Se envio un codigo QR de devolucion al correo.',
        qrUrl: qrDevolucionUrl,
      });
    }

    if (respuesta === 'Lo rompi' || respuesta === 'Lo perdi') {
      if (!metodoPago) {
        return res.status(400).json({ success: false, message: 'Metodo de pago requerido.' });
      }

      const nuevoTipo = respuesta === 'Lo rompi' ? 'rotura' : 'perdida';
      const batch = db.batch();
      batch.update(globalFormRef, formUpdate);
      batch.update(studentFormRef, formUpdate);

      if (metodoPago === 'en linea') {
        const paymentId = `PAY-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
        batch.update(adeudoRef, {
          tipo: nuevoTipo,
          respuestaFormulario: respuesta,
          metodoPagoSeleccionado: 'en linea',
          paymentId,
          fechaRespuestaFormulario: admin.firestore.Timestamp.now(),
        });
        await batch.commit();

        const paymentUrl = `${baseUrl}/pago/${paymentId}?adeudo=${adeudoId}&uid=${uid}&monto=${montoFormateado}`;

        if (correoEstudiante) {
          await sendEmail({
            from: emailFrom('Notificaciones La Salle'),
            to: correoEstudiante,
            subject: `Link de pago - ${nombreMaterial || 'Adeudo'}`,
            html: createFormPaymentLinkHtml({
              nombreEstudiante,
              nombreMaterial,
              cantidad,
              monto: montoFormateado,
              respuesta,
              paymentUrl,
            }),
          });
        }

        return res.status(200).json({
          success: true,
          message: 'Se genero el link de pago.',
          paymentUrl,
        });
      }

      if (metodoPago === 'presencial') {
        const pagoToken = randomHex(32);
        const qrPagoUrl = `${baseUrl}/scan-pago-presencial/${pagoToken}`;
        batch.update(adeudoRef, {
          tipo: nuevoTipo,
          respuestaFormulario: respuesta,
          metodoPagoSeleccionado: 'presencial',
          tokenPago: pagoToken,
          qrPagoUrl,
          fechaRespuestaFormulario: admin.firestore.Timestamp.now(),
        });
        await batch.commit();

        if (correoEstudiante) {
          await sendEmail({
            from: emailFrom('Notificaciones La Salle'),
            to: correoEstudiante,
            subject: `Codigo QR de pago presencial - ${nombreMaterial || 'Adeudo'}`,
            html: createFormPaymentQrHtml({
              nombreEstudiante,
              nombreMaterial,
              cantidad,
              monto: montoFormateado,
              codigoAdeudo,
              respuesta,
              qrUrl: qrPagoUrl,
            }),
          });
        }

        return res.status(200).json({
          success: true,
          message: 'Se envio un codigo QR de pago al correo.',
          qrUrl: qrPagoUrl,
        });
      }

      return res.status(400).json({
        success: false,
        message: 'Metodo de pago no soportado.',
      });
    }

    const batch = db.batch();
    batch.update(globalFormRef, formUpdate);
    batch.update(studentFormRef, formUpdate);
    await batch.commit();

    return res.status(200).json({
      success: true,
      message: 'Formulario respondido correctamente.',
    });
  })
);

app.post(
  '/api/admin/auth/generate-otp',
  asyncHandler(async (req, res) => {
    const adminId = String((req.body || {}).adminId || '').trim();
    if (!adminId) {
      return res.status(400).json({ message: 'El ID de administrador es requerido.' });
    }

    const adminRef = db.collection('admins').doc(adminId);
    const adminDoc = await adminRef.get();
    if (!adminDoc.exists) {
      return res.status(404).json({ message: 'La cuenta de administrador no existe.' });
    }

    const adminData = adminDoc.data() || {};
    const email = String(adminData.correo || '').trim();
    if (!email) {
      return res.status(500).json({ message: 'La cuenta no tiene correo asociado.' });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const expiresAt = admin.firestore.Timestamp.fromMillis(Date.now() + 15 * 60 * 1000);

    await db.collection('admin_auth_codes').add({
      adminId,
      otp,
      createdAt: admin.firestore.Timestamp.now(),
      expiresAt,
      used: false,
    });

    const emailResult = await sendEmail({
      from: emailFrom('Acceso La Salle Admin'),
      to: email,
      subject: `Tu codigo de acceso: ${otp}`,
      html: createOtpHtmlBody(otp),
    });

    if (!emailResult.success) {
      return res.status(502).json({
        message: 'No fue posible enviar el correo OTP. Revisa tu configuracion SMTP.',
      });
    }

    return res.status(200).json({
      message: 'Se envio un codigo de acceso a tu correo.',
      email,
    });
  })
);

app.post(
  '/api/admin/auth/verify-otp',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const adminId = String(body.adminId || '').trim();
    const otp = String(body.otp || '').trim();

    if (!adminId || !otp) {
      return res.status(400).json({
        message: 'El ID de administrador y el OTP son requeridos.',
      });
    }

    const otpSnapshot = await db
      .collection('admin_auth_codes')
      .where('adminId', '==', adminId)
      .where('otp', '==', otp)
      .limit(1)
      .get();

    if (otpSnapshot.empty) {
      return res.status(401).json({ message: 'Codigo incorrecto.' });
    }

    const otpDoc = otpSnapshot.docs[0];
    const otpData = otpDoc.data() || {};
    const nowMillis = Date.now();

    if (otpData.used) {
      return res.status(401).json({ message: 'Este codigo ya fue utilizado.' });
    }

    if (toDate(otpData.expiresAt)?.getTime() < nowMillis) {
      return res.status(401).json({ message: 'El codigo ha expirado.' });
    }

    await otpDoc.ref.update({ used: true });

    const sessionData = {
      uid: adminId,
      admin: true,
      createdAt: nowMillis,
      expiresAt: nowMillis + 5 * 24 * 60 * 60 * 1000,
    };

    setCookie(
      res,
      ADMIN_SESSION_COOKIE,
      encodeSessionCookie(sessionData),
      5 * 24 * 60 * 60 * 1000
    );

    return res.status(200).json({
      success: true,
      message: 'Acceso concedido.',
      redirectUrl: '/admin/dashboard',
    });
  })
);

app.get(
  '/api/admin/session',
  requireAdmin,
  asyncHandler(async (req, res) => {
    return res.status(200).json({
      success: true,
      admin: req.adminClaims || {},
    });
  })
);

app.post('/api/auth/session/logout', (_req, res) => {
  clearCookie(res, ADMIN_SESSION_COOKIE);
  clearCookie(res, STUDENT_SESSION_COOKIE);
  return res.status(200).json({ success: true, message: 'Sesion cerrada.' });
});

app.post(
  '/api/admins',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const email = String((req.body || {}).email || '').trim().toLowerCase();
    if (!email) {
      return res.status(400).json({ message: 'El correo es requerido.' });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ message: 'Formato de correo invalido.' });
    }

    const existingAdmin = await db
      .collection('admins')
      .where('correo', '==', email)
      .limit(1)
      .get();

    if (!existingAdmin.empty) {
      return res.status(409).json({
        message: `El correo "${email}" ya esta registrado como administrador.`,
      });
    }

    const adminOTAccount = `ADM${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
    const temporaryPassword = crypto.randomBytes(12).toString('base64').slice(0, 16);

    await db.collection('admins').doc(adminOTAccount).set({
      correo: email,
      fechaCreacion: admin.firestore.Timestamp.now(),
      rol: 'admin',
      fotoPerfil: '',
    });

    const emailResult = await sendEmail({
      from: emailFrom('Acceso La Salle Admin'),
      to: email,
      subject: 'Credenciales de administrador',
      html: createAdminCredentialsHtml(adminOTAccount, temporaryPassword),
    });

    if (!emailResult.success) {
      await db.collection('admins').doc(adminOTAccount).delete();
      return res.status(500).json({
        message: 'No fue posible enviar el correo de credenciales.',
      });
    }

    return res.status(200).json({
      message: `Administrador creado correctamente para ${email}.`,
      adminOTAccount,
    });
  })
);

app.get('/api/admin/validate-qr', (_req, res) => {
  return res.status(200).json({
    message: 'Endpoint activo. Usa POST para validar un QR.',
  });
});

app.post(
  '/api/admin/validate-qr',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const qrData = String((req.body || {}).qrData || '').trim();
    if (!qrData) {
      return res.status(400).json({ message: 'No se proporciono un codigo QR valido.' });
    }

    const cleanQrData = normalizeQrData(qrData);
    if (!cleanQrData) {
      return res.status(400).json({ message: 'No se pudo extraer un token QR valido.' });
    }

    const qrDocRef = db.collection('qrs').doc(cleanQrData);
    const qrDoc = await qrDocRef.get();

    if (qrDoc.exists) {
      const qrCodeData = qrDoc.data() || {};
      const status = qrCodeData.status;
      const operationId = qrCodeData.operationId;
      const operationType = qrCodeData.operationType;
      const studentUid = qrCodeData.studentUid;

      if (!operationId || !operationType) {
        return res.status(500).json({ message: 'El documento QR esta malformado.' });
      }

      if (status === 'validado') {
        return res.status(409).json({
          message: 'Este codigo QR ya fue utilizado.',
          details: `Operacion: ${operationType}`,
        });
      }

      if (status === 'pendiente') {
        let operationRef;
        if (operationType === 'prestamos') {
          if (!studentUid) {
            return res.status(500).json({ message: 'QR de prestamo malformado.' });
          }
          operationRef = db
            .collection('Estudiantes')
            .doc(studentUid)
            .collection('Prestamos')
            .doc(operationId);
        } else {
          operationRef = db.collection(operationType).doc(operationId);
        }

        const operationDoc = await operationRef.get();
        if (!operationDoc.exists) {
          return res.status(500).json({ message: 'La operacion asociada no existe.' });
        }

        await db.runTransaction(async (transaction) => {
          transaction.update(qrDocRef, {
            status: 'validado',
            validatedAt: admin.firestore.Timestamp.now(),
            validatedBy: req.adminClaims.uid,
          });

          if (operationType === 'prestamos') {
            transaction.update(operationRef, {
              estado: 'activo',
              fechaInicio: admin.firestore.Timestamp.now(),
            });
          } else {
            transaction.update(operationRef, { estado: 'activo' });
          }
        });

        const operationData = operationDoc.data() || {};
        return res.status(200).json({
          message: `Operacion de ${operationType} validada con exito.`,
          details: `${operationData.nombreMaterial || operationData.material || operationId}`,
        });
      }
    }

    const loanResult = await findLoanByQRToken(cleanQrData);
    if (loanResult) {
      const { studentId, studentData, loanDoc, loanData } = loanResult;

      const qrValidUntil = toDate(loanData.qrValidoHasta);
      if (qrValidUntil && qrValidUntil.getTime() < Date.now()) {
        return res.status(410).json({ message: 'Este codigo QR ha expirado.' });
      }

      await db.runTransaction(async (transaction) => {
        const completadoRef = db
          .collection('Estudiantes')
          .doc(studentId)
          .collection('Completados')
          .doc(loanDoc.id);

        transaction.set(completadoRef, {
          ...loanData,
          estado: 'devuelto',
          fechaDevolucionReal: admin.firestore.Timestamp.now(),
          validadoPor: req.adminClaims.uid,
        });
        transaction.delete(loanDoc.ref);
      });

      if (studentData.correo) {
        await sendEmail({
          from: emailFrom('Notificaciones La Salle'),
          to: studentData.correo,
          subject: `Devolucion confirmada - ${loanData.nombreMaterial || 'Prestamo'}`,
          html: createLoanReturnConfirmedHtml({
            studentName: studentData.nombre || 'Estudiante',
            materialName: loanData.nombreMaterial || 'Material',
            quantity: Number(loanData.cantidad || 0),
          }),
        });
      }

      return res.status(200).json({
        message: 'Devolucion confirmada con exito.',
        details: `${loanData.nombreMaterial || 'Material'} - Cantidad: ${loanData.cantidad || 0}`,
      });
    }

    const adeudoDevolucionResult = await findAdeudoByToken(cleanQrData, 'tokenDevolucion');
    if (adeudoDevolucionResult) {
      const { studentData, adeudoDoc, adeudoData } = adeudoDevolucionResult;

      await adeudoDoc.ref.update({
        estado: 'devuelto',
        fechaDevolucion: admin.firestore.Timestamp.now(),
        validadoPor: req.adminClaims.uid,
      });

      if (studentData.correo) {
        await sendEmail({
          from: emailFrom('Notificaciones La Salle'),
          to: studentData.correo,
          subject: 'Material devuelto - Adeudo resuelto',
          html: createDebtReturnConfirmedHtml({
            studentName: studentData.nombre || 'Estudiante',
            materialName: adeudoData.nombreMaterial || 'Material',
            quantity: Number(adeudoData.cantidad || 0),
            code: adeudoData.codigo || adeudoDoc.id,
          }),
        });
      }

      return res.status(200).json({
        message: 'Material devuelto. Adeudo resuelto.',
        details: `${adeudoData.nombreMaterial || 'Material'} - ${adeudoData.codigo || adeudoDoc.id}`,
      });
    }

    const adeudoPagoResult = await findAdeudoByToken(cleanQrData, 'tokenPago');
    if (adeudoPagoResult) {
      const { studentId, studentData, adeudoDoc, adeudoData } = adeudoPagoResult;
      const codigoPago = generatePaymentCode(adeudoData.grupo || 'XXX');

      await db.runTransaction(async (transaction) => {
        transaction.update(adeudoDoc.ref, {
          estado: 'pagado',
          fechaPago: admin.firestore.Timestamp.now(),
          codigoPago,
          validadoPor: req.adminClaims.uid,
        });

        const pagadoRef = db
          .collection('Estudiantes')
          .doc(studentId)
          .collection('Pagados')
          .doc();

        transaction.set(pagadoRef, {
          codigoPago,
          nombreMaterial: adeudoData.nombreMaterial || '',
          precio: Number(adeudoData.precio_ajustado || 0),
          metodo: 'presencial',
          estado: 'pagado',
          fechaPago: admin.firestore.Timestamp.now(),
          adeudoOriginal: adeudoDoc.id,
          grupo: adeudoData.grupo || '',
          validadoPor: req.adminClaims.uid,
        });
      });

      if (studentData.correo) {
        await sendEmail({
          from: emailFrom('Notificaciones La Salle'),
          to: studentData.correo,
          subject: `Pago confirmado - ${adeudoData.nombreMaterial || 'Adeudo'}`,
          html: createDebtPaymentConfirmedHtml({
            studentName: studentData.nombre || 'Estudiante',
            materialName: adeudoData.nombreMaterial || 'Material',
            amount: Number(adeudoData.precio_ajustado || 0),
            paymentCode: codigoPago,
          }),
        });
      }

      return res.status(200).json({
        message: 'Pago confirmado con exito.',
        details: `${adeudoData.nombreMaterial || 'Material'} - $${Number(adeudoData.precio_ajustado || 0).toFixed(2)} MXN`,
      });
    }

    return res.status(404).json({ message: 'Codigo QR no reconocido o invalido.' });
  })
);

app.get(
  ['/api/cron', '/api/cron/handle-overdue-loans'],
  requireCron,
  asyncHandler(async (_req, res) => {
    const result = await handleOverdueLoansAutomation();
    return res.status(200).json({
      success: true,
      message: 'Cron ejecutado correctamente.',
      ...result,
    });
  })
);

app.get(
  '/api/cron/check-expired-loans',
  requireCron,
  asyncHandler(async (_req, res) => {
    const result = await runCheckExpiredLoans();
    return res.status(200).json({
      success: true,
      message: `Proceso completado. ${result.processedCount} prestamos procesados.`,
      ...result,
    });
  })
);

app.get(
  '/api/cron/send-reminders',
  requireCron,
  asyncHandler(async (_req, res) => {
    const result = await runSendReminders();
    return res.status(200).json({
      success: true,
      message: 'Proceso completado.',
      timestamp: new Date().toISOString(),
      ...result,
    });
  })
);

app.get(
  '/api/cron/generate-forms',
  requireCron,
  asyncHandler(async (_req, res) => {
    const result = await runGenerateForms();
    return res.status(200).json({
      success: true,
      message: 'Proceso completado.',
      timestamp: new Date().toISOString(),
      ...result,
    });
  })
);

app.get(
  '/api/cron/estadisticas-basicas',
  requireCron,
  asyncHandler(async (_req, res) => {
    const result = await runEstadisticasBasicas();
    return res.status(200).json({
      success: true,
      message: 'Estadisticas basicas generadas.',
      timestamp: new Date().toISOString(),
      ...result,
    });
  })
);

app.get(
  '/api/cron/loan-master',
  requireCron,
  asyncHandler(async (_req, res) => {
    const results = {
      expiredLoans: 0,
      remindersSent: 0,
      formsGenerated: 0,
      overdueProcessed: 0,
      errors: [],
    };

    const expiredResult = await runCheckExpiredLoans();
    results.expiredLoans = expiredResult.processedCount;
    if (expiredResult.errors?.length) results.errors.push(...expiredResult.errors);

    const remindersResult = await runSendReminders();
    results.remindersSent = remindersResult.recordatoriosEnviados || 0;
    if (remindersResult.errors?.length) results.errors.push(...remindersResult.errors);

    const currentHour = new Date().getHours();
    if (currentHour % 6 === 0) {
      const formsResult = await runGenerateForms();
      results.formsGenerated = formsResult.formulariosCreados || 0;
      if (formsResult.errors?.length) results.errors.push(...formsResult.errors);
    }

    const overdueResult = await handleOverdueLoansAutomation();
    results.overdueProcessed = overdueResult.processedLoans || 0;

    return res.status(200).json({
      success: true,
      message: 'Loan Master Cron ejecutado.',
      timestamp: new Date().toISOString(),
      ...results,
    });
  })
);

app.get(
  '/api/estadisticas/obtener',
  asyncHandler(async (_req, res) => {
    const estadisticasDoc = await db.collection('Estadisticas').doc('reporte_actual').get();
    if (!estadisticasDoc.exists) {
      return res.status(200).json(defaultStatsPayload());
    }

    const data = estadisticasDoc.data() || {};
    return res.status(200).json({
      topMateriales: data.topMateriales || [],
      topPerdidos: data.topPerdidos || [],
      topEstudiantes: data.topEstudiantes || [],
      peoresEstudiantes: data.peoresEstudiantes || [],
      totalPrestamos: Number(data.totalPrestamos || 0),
      totalAdeudos: Number(data.totalAdeudos || 0),
      totalCompletados: Number(data.totalCompletados || 0),
      totalEstudiantes: Number(data.totalEstudiantes || 0),
      analisisIA: data.analisisIA || defaultStatsPayload().analisisIA,
      ultimaActualizacion: toISO(data.ultimaActualizacion),
      ultimaActualizacionIA: toISO(data.ultimaActualizacionIA),
      version: data.version || Date.now(),
    });
  })
);

app.post(
  ['/api/admin/estadisticas', '/api/admin/generar-analisis-ia'],
  requireAdmin,
  asyncHandler(async (_req, res) => {
    const reporteRef = db.collection('Estadisticas').doc('reporte_actual');
    const reporteSnap = await reporteRef.get();
    if (!reporteSnap.exists) {
      return res.status(400).json({
        success: false,
        message: 'No hay estadisticas disponibles para analizar.',
      });
    }

    const datosActuales = reporteSnap.data() || {};
    const analisis = buildBasicAnalysisFromStats(datosActuales);

    await reporteRef.set(
      {
        analisisIA: analisis,
        ultimaActualizacionIA: admin.firestore.FieldValue.serverTimestamp(),
        datosUltimoAnalisis: {
          totalPrestamos: Number(datosActuales.totalPrestamos || 0),
          totalAdeudos: Number(datosActuales.totalAdeudos || 0),
          totalCompletados: Number(datosActuales.totalCompletados || 0),
        },
      },
      { merge: true }
    );

    return res.status(200).json({
      success: true,
      message: 'Analisis generado y guardado.',
      analisis,
      timestamp: new Date().toISOString(),
    });
  })
);

app.post(
  '/api/genkit',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const prompt = String(body.prompt || '').trim();
    const student = body.student || {};

    if (!prompt) {
      return res.status(400).json({ error: 'El prompt es requerido.' });
    }

    const response = await buildFallbackChatResponse(prompt, student);
    return res.status(200).json({ response });
  })
);

app.post(
  '/api/chat',
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const studentUid = String(body.studentUid || '').trim();
    if (!studentUid) {
      return res.status(400).json({ error: 'Missing studentUid.' });
    }

    const studentDoc = await db.collection('Estudiantes').doc(studentUid).get();
    const studentName = studentDoc.exists ? (studentDoc.data() || {}).nombre || 'estudiante' : 'estudiante';
    const response = `Hola ${studentName}. Genkit fue retirado de esta version, pero el backend sigue activo para prestamos, adeudos y pagos.`;

    return res.status(200).json({ response });
  })
);

app.use((error, _req, res, _next) => {
  console.error('[ERROR]', error);
  if (res.headersSent) return;
  res.status(500).json({
    success: false,
    message: 'Error interno del servidor.',
    error: error.message || 'Unknown error',
  });
});

app.listen(PORT, () => {
  console.log(`Backend listo en http://localhost:${PORT}`);
});

module.exports = { app };
