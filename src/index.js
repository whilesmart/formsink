import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';
import nodemailer from 'nodemailer';
import { forms, submissions } from './db.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const API_KEY = process.env.API_KEY;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

const sessions = new Map();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    const globalOrigins = process.env.ALLOWED_ORIGINS?.split(',').map(o => o.trim()).filter(Boolean);
    if (!origin || !globalOrigins?.length || globalOrigins.includes(origin)) {
      return callback(null, true);
    }
    const allForms = forms.list();
    const allAllowedOrigins = allForms.flatMap(f => f.allowedOrigins || []);
    if (allAllowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    callback(null, true);
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

function createSession() {
  const token = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 24 * 60 * 60 * 1000;
  sessions.set(token, { expires });
  return token;
}

function validateSession(token) {
  const session = sessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expires) {
    sessions.delete(token);
    return false;
  }
  return true;
}

function requireAuth(req, res, next) {
  const token = req.cookies.session;
  if (validateSession(token)) return next();
  if (req.path.startsWith('/admin/api/')) return res.status(401).json({ error: 'Unauthorized' });
  res.redirect('/admin/login');
}

function requireApiKey(req, res, next) {
  if (!API_KEY) return next();
  const key = req.headers['x-api-key'];
  if (key === API_KEY) return next();
  return res.status(401).json({ error: 'Invalid API key' });
}

let transporter = null;
if (process.env.SMTP_HOST) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587'),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendNotification(toEmail, formName, data, submittedAt) {
  if (!transporter || !toEmail) return;
  const entries = Object.entries(data).filter(([key]) => !key.startsWith('_'));
  const formattedData = entries.map(([k, v]) => `${k}: ${v}`).join('\n');
  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || 'noreply@formsink.local',
      to: toEmail,
      subject: `New submission: ${formName}`,
      text: `New form submission:\n\n${formattedData}\n\nSubmitted: ${submittedAt}`,
      html: `
        <h2>New submission: ${formName}</h2>
        <table style="border-collapse:collapse;width:100%">
          ${entries.map(([k, v]) => `
            <tr>
              <td style="border:1px solid #ddd;padding:8px;font-weight:bold">${k}</td>
              <td style="border:1px solid #ddd;padding:8px">${v}</td>
            </tr>
          `).join('')}
        </table>
        <p style="color:#666;margin-top:16px">Submitted: ${submittedAt}</p>
      `,
    });
  } catch (err) {
    console.error('Email failed:', err.message);
  }
}

// ============ AUTH ROUTES ============

app.get('/admin/login', (req, res) => {
  if (validateSession(req.cookies.session)) return res.redirect('/admin');
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - FormSink</title>
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #1a1a2e; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login-card { background: #16213e; padding: 32px; border-radius: 4px; box-shadow: 0 8px 32px rgba(0,0,0,0.3); width: 100%; max-width: 380px; border: 1px solid #1f3460; }
    .login-card h1 { font-size: 22px; margin-bottom: 6px; color: #e8e8e8; font-weight: 600; }
    .login-card p { color: #8892a6; margin-bottom: 28px; font-size: 14px; }
    .form-group { margin-bottom: 20px; }
    .form-group label { display: block; font-size: 13px; font-weight: 500; margin-bottom: 8px; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.5px; }
    .form-group input { width: 100%; padding: 12px 14px; border: 1px solid #2d3a5c; border-radius: 3px; font-size: 14px; background: #0f1629; color: #e8e8e8; transition: all 0.2s; }
    .form-group input:focus { outline: none; border-color: #4a6fa5; background: #131b2e; }
    .form-group input::placeholder { color: #4a5568; }
    .btn { width: 100%; padding: 12px; background: #4a6fa5; color: #fff; border: none; border-radius: 3px; font-size: 14px; font-weight: 500; cursor: pointer; transition: all 0.2s; }
    .btn:hover { background: #5a7fb5; }
    .btn:disabled { background: #2d3a5c; color: #6b7280; cursor: not-allowed; }
    .error { background: rgba(220, 53, 69, 0.15); color: #f87171; padding: 12px; border-radius: 3px; margin-bottom: 20px; font-size: 13px; border: 1px solid rgba(220, 53, 69, 0.3); }
  </style>
</head>
<body>
  <div id="app">
    <div class="login-card">
      <h1>FormSink</h1>
      <p>Sign in to manage your forms</p>
      <div v-if="error" class="error">{{ error }}</div>
      <form @submit.prevent="login">
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" v-model="password" placeholder="Enter password" required autofocus>
        </div>
        <button type="submit" class="btn" :disabled="loading">{{ loading ? 'Signing in...' : 'Sign In' }}</button>
      </form>
    </div>
  </div>
  <script>
    const { createApp, ref } = Vue;
    createApp({
      setup() {
        const password = ref('');
        const error = ref('');
        const loading = ref(false);
        const login = async () => {
          error.value = '';
          loading.value = true;
          try {
            const res = await fetch('/admin/login', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ password: password.value })
            });
            if (res.ok) window.location.href = '/admin';
            else error.value = (await res.json()).error || 'Invalid password';
          } catch (e) { error.value = 'Connection error'; }
          loading.value = false;
        };
        return { password, error, loading, login };
      }
    }).mount('#app');
  </script>
</body>
</html>`);
});

app.post('/admin/login', (req, res) => {
  const { password } = req.body;
  if (password === ADMIN_PASSWORD) {
    const token = createSession();
    res.cookie('session', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000,
    });
    return res.json({ success: true });
  }
  res.status(401).json({ error: 'Invalid password' });
});

app.post('/admin/logout', (req, res) => {
  const token = req.cookies.session;
  if (token) sessions.delete(token);
  res.clearCookie('session');
  res.redirect('/admin/login');
});

// ============ ADMIN UI ============

app.get('/admin', requireAuth, (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FormSink Admin</title>
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f1629; min-height: 100vh; color: #e8e8e8; }

    .sidebar { position: fixed; left: 0; top: 0; bottom: 0; width: 220px; background: #1a1a2e; border-right: 1px solid #2d3a5c; padding: 20px 0; }
    .sidebar-header { padding: 0 20px 20px; border-bottom: 1px solid #2d3a5c; margin-bottom: 20px; }
    .sidebar-header h1 { font-size: 18px; font-weight: 600; color: #e8e8e8; }
    .sidebar-nav { padding: 0 12px; }
    .nav-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: 3px; color: #8892a6; font-size: 14px; cursor: pointer; transition: all 0.15s; margin-bottom: 4px; }
    .nav-item:hover { background: #16213e; color: #e8e8e8; }
    .nav-item.active { background: #4a6fa5; color: #fff; }
    .sidebar-footer { position: absolute; bottom: 0; left: 0; right: 0; padding: 16px 12px; border-top: 1px solid #2d3a5c; }

    .main { margin-left: 220px; padding: 24px 32px; min-height: 100vh; }

    .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid #2d3a5c; }
    .page-header h2 { font-size: 20px; font-weight: 600; color: #e8e8e8; }

    .stats-row { display: flex; gap: 16px; margin-bottom: 28px; }
    .stat-card { background: #16213e; padding: 20px; border-radius: 4px; border: 1px solid #2d3a5c; flex: 1; }
    .stat-card .label { font-size: 12px; color: #8892a6; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px; }
    .stat-card .value { font-size: 32px; font-weight: 600; color: #e8e8e8; }

    .table-container { background: #16213e; border-radius: 4px; border: 1px solid #2d3a5c; overflow: hidden; }
    .table-header { display: flex; justify-content: space-between; align-items: center; padding: 16px 20px; border-bottom: 1px solid #2d3a5c; }
    .table-header h3 { font-size: 14px; font-weight: 600; color: #e8e8e8; }

    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 14px 20px; border-bottom: 1px solid #2d3a5c; }
    th { font-size: 11px; font-weight: 600; color: #8892a6; text-transform: uppercase; letter-spacing: 0.5px; background: #131b2e; }
    td { font-size: 14px; color: #c9d1d9; }
    tr:hover td { background: #1a2744; }
    tr:last-child td { border-bottom: none; }

    .slug-badge { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 12px; color: #8892a6; background: #0f1629; padding: 4px 8px; border-radius: 2px; }
    .endpoint-badge { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 11px; color: #4a6fa5; }
    .count-badge { font-size: 13px; color: #8892a6; }

    .btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px; border-radius: 3px; font-size: 13px; font-weight: 500; cursor: pointer; border: none; transition: all 0.15s; }
    .btn-primary { background: #4a6fa5; color: #fff; }
    .btn-primary:hover { background: #5a7fb5; }
    .btn-secondary { background: #2d3a5c; color: #c9d1d9; }
    .btn-secondary:hover { background: #3d4a6c; }
    .btn-ghost { background: transparent; color: #8892a6; padding: 6px 10px; }
    .btn-ghost:hover { color: #e8e8e8; background: #2d3a5c; }
    .btn-danger { background: transparent; color: #f87171; }
    .btn-danger:hover { background: rgba(248, 113, 113, 0.1); }
    .btn-sm { padding: 6px 10px; font-size: 12px; }

    .actions { display: flex; gap: 4px; }

    .modal-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.7); display: flex; align-items: center; justify-content: center; z-index: 100; }
    .modal { background: #16213e; border-radius: 4px; width: 100%; max-width: 480px; max-height: 90vh; overflow-y: auto; border: 1px solid #2d3a5c; }
    .modal-header { padding: 20px; border-bottom: 1px solid #2d3a5c; display: flex; justify-content: space-between; align-items: center; }
    .modal-header h2 { font-size: 16px; font-weight: 600; color: #e8e8e8; }
    .modal-body { padding: 20px; }
    .modal-footer { padding: 16px 20px; border-top: 1px solid #2d3a5c; display: flex; justify-content: flex-end; gap: 10px; }

    .form-group { margin-bottom: 18px; }
    .form-group:last-child { margin-bottom: 0; }
    .form-group label { display: block; font-size: 12px; font-weight: 500; margin-bottom: 6px; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.5px; }
    .form-group input { width: 100%; padding: 10px 12px; border: 1px solid #2d3a5c; border-radius: 3px; font-size: 14px; background: #0f1629; color: #e8e8e8; transition: all 0.15s; }
    .form-group input:focus { outline: none; border-color: #4a6fa5; }
    .form-group input:disabled { background: #1a1a2e; color: #6b7280; cursor: not-allowed; }
    .form-group .hint { font-size: 11px; color: #6b7280; margin-top: 6px; }
    .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }

    .close-btn { background: none; border: none; font-size: 20px; cursor: pointer; color: #6b7280; padding: 0; line-height: 1; }
    .close-btn:hover { color: #e8e8e8; }

    .empty-state { text-align: center; padding: 48px 24px; color: #6b7280; }
    .empty-state p { margin-bottom: 16px; }

    .alert { padding: 12px 16px; border-radius: 3px; margin-bottom: 20px; font-size: 13px; }
    .alert-success { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
    .alert-error { background: rgba(220, 53, 69, 0.15); color: #f87171; border: 1px solid rgba(220, 53, 69, 0.3); }

    .data-json { font-family: 'SF Mono', Monaco, Consolas, monospace; font-size: 11px; background: #0f1629; padding: 10px; border-radius: 3px; white-space: pre-wrap; word-break: break-all; max-height: 120px; overflow-y: auto; color: #a0aec0; border: 1px solid #2d3a5c; }

    .submissions-modal { max-width: 720px; }
    .submissions-empty { padding: 40px; text-align: center; color: #6b7280; }

    @media (max-width: 768px) {
      .sidebar { display: none; }
      .main { margin-left: 0; padding: 16px; }
      .form-row { grid-template-columns: 1fr; }
      .stats-row { flex-direction: column; }
    }
  </style>
</head>
<body>
  <div id="app">
    <aside class="sidebar">
      <div class="sidebar-header">
        <h1>FormSink</h1>
      </div>
      <nav class="sidebar-nav">
        <div class="nav-item active">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Forms
        </div>
      </nav>
      <div class="sidebar-footer">
        <form action="/admin/logout" method="POST">
          <button type="submit" class="btn btn-ghost" style="width:100%;justify-content:center">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Logout
          </button>
        </form>
      </div>
    </aside>

    <main class="main">
      <transition name="fade">
        <div v-if="alert.message" :class="['alert', 'alert-' + alert.type]">{{ alert.message }}</div>
      </transition>

      <div class="page-header">
        <h2>Dashboard</h2>
        <button class="btn btn-primary" @click="openModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New Form
        </button>
      </div>

      <div class="stats-row">
        <div class="stat-card">
          <div class="label">Total Forms</div>
          <div class="value">{{ forms.length }}</div>
        </div>
        <div class="stat-card">
          <div class="label">Total Submissions</div>
          <div class="value">{{ totalSubmissions }}</div>
        </div>
      </div>

      <div class="table-container">
        <div class="table-header">
          <h3>All Forms</h3>
        </div>
        <div v-if="forms.length === 0" class="empty-state">
          <p>No forms yet. Create your first form to start collecting submissions.</p>
          <button class="btn btn-primary" @click="openModal()">Create Form</button>
        </div>
        <table v-else>
          <thead>
            <tr>
              <th>Name</th>
              <th>Slug</th>
              <th>Submissions</th>
              <th>Endpoint</th>
              <th style="width:140px">Actions</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="form in forms" :key="form.slug">
              <td><strong>{{ form.name }}</strong></td>
              <td><span class="slug-badge">{{ form.slug }}</span></td>
              <td><span class="count-badge">{{ form.submissionCount }}</span></td>
              <td><span class="endpoint-badge">POST /api/f/{{ form.slug }}</span></td>
              <td>
                <div class="actions">
                  <button class="btn btn-ghost btn-sm" @click="viewSubmissions(form)" title="View submissions">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                  </button>
                  <button class="btn btn-ghost btn-sm" @click="openModal(form)" title="Edit">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                  </button>
                  <button class="btn btn-danger btn-sm" @click="deleteForm(form)" title="Delete">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3,6 5,6 21,6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </main>

    <teleport to="body">
      <div v-if="showModal" class="modal-overlay" @click.self="closeModal">
        <div class="modal">
          <div class="modal-header">
            <h2>{{ editingForm ? 'Edit Form' : 'New Form' }}</h2>
            <button class="close-btn" @click="closeModal">&times;</button>
          </div>
          <form @submit.prevent="saveForm">
            <div class="modal-body">
              <div class="form-row">
                <div class="form-group">
                  <label>Slug</label>
                  <input type="text" v-model="formData.slug" required placeholder="my-form" :disabled="editingForm">
                  <div class="hint">Lowercase, numbers, hyphens only</div>
                </div>
                <div class="form-group">
                  <label>Name</label>
                  <input type="text" v-model="formData.name" required placeholder="My Contact Form">
                </div>
              </div>
              <div class="form-group">
                <label>Notification Email</label>
                <input type="email" v-model="formData.notifyEmail" placeholder="team@example.com">
                <div class="hint">Receive email on new submissions</div>
              </div>
              <div class="form-group">
                <label>Redirect URL</label>
                <input type="url" v-model="formData.redirectUrl" placeholder="https://example.com/thank-you">
                <div class="hint">Redirect after HTML form submission</div>
              </div>
              <div class="form-group">
                <label>Allowed Origins</label>
                <input type="text" v-model="formData.allowedOrigins" placeholder="https://example.com, https://app.example.com">
                <div class="hint">Comma-separated domains (leave empty to allow all)</div>
              </div>
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" @click="closeModal">Cancel</button>
              <button type="submit" class="btn btn-primary" :disabled="saving">{{ saving ? 'Saving...' : 'Save Form' }}</button>
            </div>
          </form>
        </div>
      </div>
    </teleport>

    <teleport to="body">
      <div v-if="showSubmissions" class="modal-overlay" @click.self="closeSubmissions">
        <div class="modal submissions-modal">
          <div class="modal-header">
            <h2>Submissions: {{ selectedForm?.name }}</h2>
            <button class="close-btn" @click="closeSubmissions">&times;</button>
          </div>
          <div v-if="submissions.length === 0" class="submissions-empty">No submissions yet</div>
          <table v-else>
            <thead>
              <tr>
                <th style="width:160px">Date</th>
                <th>Data</th>
                <th style="width:100px">IP</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="sub in submissions" :key="sub.id">
                <td>{{ formatDate(sub.createdAt) }}</td>
                <td><div class="data-json">{{ JSON.stringify(sub.data, null, 2) }}</div></td>
                <td>{{ sub.ip || '-' }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </teleport>
  </div>

  <script>
    const { createApp, ref, computed, onMounted } = Vue;
    createApp({
      setup() {
        const forms = ref([]);
        const alert = ref({ message: '', type: 'success' });
        const showModal = ref(false);
        const showSubmissions = ref(false);
        const editingForm = ref(null);
        const selectedForm = ref(null);
        const submissions = ref([]);
        const saving = ref(false);
        const formData = ref({ slug: '', name: '', notifyEmail: '', redirectUrl: '', allowedOrigins: '' });

        const totalSubmissions = computed(() => forms.value.reduce((sum, f) => sum + f.submissionCount, 0));

        const showAlert = (message, type = 'success') => {
          alert.value = { message, type };
          setTimeout(() => alert.value = { message: '', type: 'success' }, 3000);
        };

        const loadForms = async () => {
          const res = await fetch('/admin/api/forms');
          if (res.status === 401) return window.location.href = '/admin/login';
          forms.value = await res.json();
        };

        const openModal = (form = null) => {
          editingForm.value = form;
          formData.value = form ? {
            slug: form.slug, name: form.name, notifyEmail: form.notifyEmail || '',
            redirectUrl: form.redirectUrl || '', allowedOrigins: (form.allowedOrigins || []).join(', ')
          } : { slug: '', name: '', notifyEmail: '', redirectUrl: '', allowedOrigins: '' };
          showModal.value = true;
        };

        const closeModal = () => { showModal.value = false; editingForm.value = null; };

        const saveForm = async () => {
          if (!editingForm.value && !/^[a-z0-9-]+$/.test(formData.value.slug)) {
            return showAlert('Slug must contain only lowercase letters, numbers, and hyphens', 'error');
          }
          saving.value = true;
          const data = { ...formData.value, allowedOrigins: formData.value.allowedOrigins.split(',').map(s => s.trim()).filter(Boolean) };
          const url = editingForm.value ? '/admin/api/forms/' + editingForm.value.slug : '/admin/api/forms';
          try {
            const res = await fetch(url, { method: editingForm.value ? 'PUT' : 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
            if (res.status === 401) return window.location.href = '/admin/login';
            if (res.ok) { showAlert(editingForm.value ? 'Form updated' : 'Form created'); closeModal(); loadForms(); }
            else showAlert((await res.json()).error || 'Failed to save', 'error');
          } catch (e) { showAlert('Network error', 'error'); }
          saving.value = false;
        };

        const deleteForm = async (form) => {
          if (!confirm('Delete "' + form.name + '" and all submissions?')) return;
          try {
            const res = await fetch('/admin/api/forms/' + form.slug, { method: 'DELETE' });
            if (res.status === 401) return window.location.href = '/admin/login';
            if (res.ok) { showAlert('Form deleted'); loadForms(); }
            else showAlert('Failed to delete', 'error');
          } catch (e) { showAlert('Network error', 'error'); }
        };

        const viewSubmissions = async (form) => {
          selectedForm.value = form;
          try {
            const res = await fetch('/admin/api/submissions/' + form.slug);
            if (res.status === 401) return window.location.href = '/admin/login';
            submissions.value = await res.json();
            showSubmissions.value = true;
          } catch (e) { showAlert('Failed to load submissions', 'error'); }
        };

        const closeSubmissions = () => { showSubmissions.value = false; selectedForm.value = null; };
        const formatDate = (date) => new Date(date).toLocaleString();

        onMounted(loadForms);

        return { forms, alert, showModal, showSubmissions, editingForm, selectedForm, submissions, saving, formData, totalSubmissions, showAlert, openModal, closeModal, saveForm, deleteForm, viewSubmissions, closeSubmissions, formatDate };
      }
    }).mount('#app');
  </script>
</body>
</html>`);
});

// Admin API (session-protected)
app.get('/admin/api/forms', requireAuth, (req, res) => {
  const allForms = forms.list();
  res.json(allForms.map(f => ({ ...f, submissionCount: submissions.countByForm(f.slug) })));
});

app.post('/admin/api/forms', requireAuth, (req, res) => {
  const { slug, name, notifyEmail, redirectUrl, allowedOrigins } = req.body;
  if (!slug || !name) return res.status(400).json({ error: 'slug and name are required' });
  if (!/^[a-z0-9-]+$/.test(slug)) return res.status(400).json({ error: 'Invalid slug format' });
  if (forms.get(slug)) return res.status(409).json({ error: 'Slug already exists' });
  res.status(201).json(forms.create({ slug, name, notifyEmail, redirectUrl, allowedOrigins }));
});

app.put('/admin/api/forms/:slug', requireAuth, (req, res) => {
  const form = forms.update(req.params.slug, req.body);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json(form);
});

app.delete('/admin/api/forms/:slug', requireAuth, (req, res) => {
  if (!forms.delete(req.params.slug)) return res.status(404).json({ error: 'Form not found' });
  submissions.deleteByForm(req.params.slug);
  res.json({ message: 'Deleted' });
});

app.get('/admin/api/submissions/:slug', requireAuth, (req, res) => {
  res.json(submissions.listByForm(req.params.slug, { limit: parseInt(req.query.limit) || 100, offset: parseInt(req.query.offset) || 0 }));
});

// External API (API key protected)
app.get('/api/forms', requireApiKey, (req, res) => res.json(forms.list()));
app.get('/api/forms/:slug', requireApiKey, (req, res) => {
  const form = forms.get(req.params.slug);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json(form);
});

app.post('/api/forms', requireApiKey, (req, res) => {
  const { slug, name, notifyEmail, redirectUrl, allowedOrigins } = req.body;
  if (!slug || !name) return res.status(400).json({ error: 'slug and name are required' });
  if (!/^[a-z0-9-]+$/.test(slug)) return res.status(400).json({ error: 'Invalid slug format' });
  if (forms.get(slug)) return res.status(409).json({ error: 'Slug already exists' });
  const form = forms.create({ slug, name, notifyEmail, redirectUrl, allowedOrigins });
  res.status(201).json({ ...form, endpoint: `/api/f/${slug}` });
});

app.put('/api/forms/:slug', requireApiKey, (req, res) => {
  const form = forms.update(req.params.slug, req.body);
  if (!form) return res.status(404).json({ error: 'Form not found' });
  res.json(form);
});

app.delete('/api/forms/:slug', requireApiKey, (req, res) => {
  if (!forms.delete(req.params.slug)) return res.status(404).json({ error: 'Form not found' });
  submissions.deleteByForm(req.params.slug);
  res.json({ message: 'Deleted' });
});

app.get('/api/submissions/:slug', requireApiKey, (req, res) => {
  res.json(submissions.listByForm(req.params.slug, { limit: parseInt(req.query.limit) || 100, offset: parseInt(req.query.offset) || 0 }));
});

// Public submission
app.post('/api/f/:slug', async (req, res) => {
  const form = forms.get(req.params.slug);
  if (!form) return res.status(404).json({ error: 'Form not found' });

  const origin = req.get('origin');
  if (form.allowedOrigins?.length > 0 && origin && !form.allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Origin not allowed' });
  }

  const id = uuidv4();
  const submission = submissions.create({ id, formSlug: req.params.slug, data: req.body, ip: req.ip, userAgent: req.get('user-agent') });
  await sendNotification(form.notifyEmail, form.name, req.body, submission.createdAt);

  if (form.redirectUrl && req.get('content-type')?.includes('application/x-www-form-urlencoded')) {
    return res.redirect(form.redirectUrl);
  }
  res.status(201).json({ success: true, id, message: 'Submission received' });
});

app.get('/health', (req, res) => res.json({ status: 'ok', timestamp: new Date().toISOString() }));

app.listen(PORT, () => {
  console.log(`FormSink running on http://localhost:${PORT}`);
  console.log(`Admin UI: http://localhost:${PORT}/admin`);
});
