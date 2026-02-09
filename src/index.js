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
const PORT = process.env.PORT || 3000;
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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            ink: '#0b0f1a',
            panel: '#121826',
            panelStrong: '#0f1624',
            line: '#1f2a44',
            accent: '#f97316',
            accentSoft: '#fdba74',
            success: '#22c55e',
            danger: '#f43f5e'
          },
          fontFamily: {
            sans: ['Space Grotesk', 'ui-sans-serif', 'system-ui'],
            mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular']
          },
          boxShadow: {
            soft: '0 12px 30px rgba(2, 6, 23, 0.45)'
          },
          keyframes: {
            floatIn: { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
            fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } }
          },
          animation: {
            'float-in': 'floatIn 240ms ease-out',
            'fade-in': 'fadeIn 200ms ease-out'
          }
        }
      }
    };
  </script>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
  <style>
    body {
      background:
        radial-gradient(900px 520px at 12% -8%, rgba(249, 115, 22, 0.22), transparent 60%),
        radial-gradient(700px 420px at 110% 10%, rgba(34, 197, 94, 0.18), transparent 60%),
        #0b0f1a;
    }
    .fade-enter-active, .fade-leave-active { transition: opacity 200ms ease; }
    .fade-enter-from, .fade-leave-to { opacity: 0; }
  </style>
</head>
<body class="min-h-screen font-sans text-slate-100">
  <div id="app" class="min-h-screen flex items-center justify-center px-4 py-10">
    <div class="w-full max-w-md border border-line/80 bg-panel/95 p-8 shadow-soft animate-float-in">
      <div class="flex items-center gap-3">
        <div class="flex h-11 w-11 items-center justify-center bg-accent/15 text-accent font-semibold">FS</div>
        <div>
          <div class="text-xs uppercase tracking-[0.3em] text-slate-400">FormSink</div>
          <h1 class="text-xl font-semibold text-slate-100">Admin Console</h1>
        </div>
      </div>
      <p class="mt-4 text-sm text-slate-400">Sign in to manage forms, review submissions, and update webhooks.</p>
      <transition name="fade">
        <div v-if="error" class="mt-6 border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-rose-200">
          {{ error }}
        </div>
      </transition>
      <form @submit.prevent="login" class="mt-6 space-y-5">
        <div>
          <label for="password" class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Password</label>
          <input
            type="password"
            id="password"
            v-model="password"
            placeholder="Enter password"
            required
            autofocus
            class="mt-2 w-full border border-line bg-slate-800 px-4 py-3 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40"
          >
        </div>
        <button
          type="submit"
          class="inline-flex w-full items-center justify-center gap-2 bg-accent px-4 py-3 text-sm font-semibold text-ink shadow-soft transition hover:bg-accentSoft disabled:cursor-not-allowed disabled:opacity-60"
          :disabled="loading"
        >
          <span v-if="loading" class="inline-flex h-4 w-4 animate-spin rounded-full border-2 border-ink/60 border-t-transparent"></span>
          {{ loading ? 'Signing in...' : 'Sign In' }}
        </button>
      </form>
      <div class="mt-6 flex items-center justify-between text-xs text-slate-500">
        <span>Secure session 24h</span>
        <span class="font-mono">POST /admin/login</span>
      </div>
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
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script>
    tailwind.config = {
      theme: {
        extend: {
          colors: {
            ink: '#0b0f1a',
            panel: '#121826',
            panelStrong: '#0f1624',
            line: '#1f2a44',
            accent: '#f97316',
            accentSoft: '#fdba74',
            success: '#22c55e',
            danger: '#f43f5e'
          },
          fontFamily: {
            sans: ['Space Grotesk', 'ui-sans-serif', 'system-ui'],
            mono: ['JetBrains Mono', 'ui-monospace', 'SFMono-Regular']
          },
          boxShadow: {
            soft: '0 12px 30px rgba(2, 6, 23, 0.45)'
          },
          keyframes: {
            floatIn: { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
            fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } }
          },
          animation: {
            'float-in': 'floatIn 240ms ease-out',
            'fade-in': 'fadeIn 200ms ease-out'
          }
        }
      }
    };
  </script>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/vue@3/dist/vue.global.prod.js"></script>
  <style>
    body {
      background:
        radial-gradient(1100px 620px at 8% -10%, rgba(249, 115, 22, 0.22), transparent 60%),
        radial-gradient(900px 520px at 108% 12%, rgba(34, 197, 94, 0.18), transparent 60%),
        #0b0f1a;
    }
    .fade-enter-active, .fade-leave-active { transition: opacity 200ms ease; }
    .fade-enter-from, .fade-leave-to { opacity: 0; }

  </style>
</head>
<body class="min-h-screen font-sans text-slate-100">
  <div id="app" class="min-h-screen">
    <aside class="hidden lg:flex lg:fixed lg:inset-y-0 lg:w-60 lg:flex-col lg:border-r lg:border-line/80 lg:bg-panel/95">
      <div class="flex items-center gap-3 px-6 py-6">
        <div class="flex h-11 w-11 items-center justify-center bg-accent/15 text-accent font-semibold">FS</div>
        <div>
          <div class="text-xs uppercase tracking-[0.3em] text-slate-400">FormSink</div>
          <div class="text-lg font-semibold">Admin Console</div>
        </div>
      </div>
      <nav class="px-4">
        <div class="flex items-center gap-3 bg-accent/15 px-4 py-3 text-sm font-semibold text-accent">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          Forms
        </div>
        <div class="mt-4 border border-line/60 bg-panelStrong/70 px-4 py-4 text-xs text-slate-400">
          Manage endpoints and alert routing. All changes apply immediately.
        </div>
      </nav>
      <div class="mt-auto px-4 py-6">
        <form action="/admin/logout" method="POST">
          <button type="submit" class="inline-flex w-full items-center justify-center gap-2 border border-line/80 bg-panelStrong/80 px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:border-accent/60 hover:text-white">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            Logout
          </button>
        </form>
      </div>
    </aside>

    <main class="px-4 py-6 sm:px-6 lg:ml-60 lg:px-8">
      <div class="mb-8 flex flex-col gap-4 lg:hidden">
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-3">
            <div class="flex h-10 w-10 items-center justify-center bg-accent/15 text-accent font-semibold">FS</div>
            <div>
              <div class="text-xs uppercase tracking-[0.3em] text-slate-400">FormSink</div>
              <div class="text-lg font-semibold">Admin Console</div>
            </div>
          </div>
          <form action="/admin/logout" method="POST">
            <button type="submit" class="inline-flex items-center gap-2 border border-line/80 bg-panelStrong/80 px-3 py-2 text-xs font-semibold text-slate-200">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/><polyline points="16,17 21,12 16,7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
              Logout
            </button>
          </form>
        </div>
      </div>

      <transition name="fade">
        <div v-if="alert.message" :class="['mb-5 border px-4 py-3 text-sm animate-fade-in', alert.type === 'success' ? 'border-success/50 bg-success/10 text-emerald-200' : 'border-danger/50 bg-danger/10 text-rose-200']">
          {{ alert.message }}
        </div>
      </transition>

      <div class="flex flex-wrap items-center gap-x-5 gap-y-3">
        <h2 class="text-xl font-semibold">Forms</h2>
        <div class="flex items-center gap-2">
          <span class="border border-line/70 bg-panelStrong/70 px-2.5 py-1 text-xs"><span class="font-semibold text-slate-100">{{ forms.length }}</span> <span class="text-slate-400">forms</span></span>
          <span class="border border-line/70 bg-panelStrong/70 px-2.5 py-1 text-xs"><span class="font-semibold text-slate-100">{{ totalSubmissions }}</span> <span class="text-slate-400">submissions</span></span>
        </div>
        <button class="ml-auto inline-flex items-center gap-2 bg-accent px-3.5 py-2 text-sm font-semibold text-ink shadow-soft transition hover:bg-accentSoft" @click="openModal()">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          New Form
        </button>
      </div>

      <div class="mt-4 border border-line/70 bg-panel/90 shadow-soft">
        <div v-if="forms.length === 0" class="px-6 py-14 text-center">
          <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="mx-auto text-slate-600"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          <p class="mt-3 text-sm text-slate-400">No forms yet. Create your first form to start collecting submissions.</p>
          <button class="mt-4 inline-flex items-center gap-2 bg-accent px-4 py-2.5 text-sm font-semibold text-ink shadow-soft transition hover:bg-accentSoft" @click="openModal()">Create Form</button>
        </div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-panelStrong/70 text-xs uppercase tracking-[0.3em] text-slate-400">
              <tr>
                <th class="px-5 py-3 font-semibold">Name</th>
                <th class="px-5 py-3 font-semibold">Slug</th>
                <th class="px-5 py-3 font-semibold">Submissions</th>
                <th class="px-5 py-3 font-semibold">Endpoint</th>
                <th class="px-5 py-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="form in forms" :key="form.slug" class="border-b border-line/60 hover:bg-panelStrong/60 transition">
                <td class="px-5 py-4 font-semibold text-slate-100">{{ form.name }}</td>
                <td class="px-5 py-4">
                  <span class="inline-flex items-center border border-line/70 bg-panelStrong/70 px-2 py-1 font-mono text-xs text-slate-300">{{ form.slug }}</span>
                </td>
                <td class="px-5 py-4 text-slate-300">{{ form.submissionCount }}</td>
                <td class="px-5 py-4">
                  <div class="flex items-center gap-2">
                    <span class="font-mono text-xs text-accent">POST /api/f/{{ form.slug }}</span>
                    <button class="inline-flex h-6 w-6 items-center justify-center text-slate-500 transition hover:bg-panelStrong hover:text-white" @click="copyEndpoint(form.slug)" title="Copy endpoint URL">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
                    </button>
                  </div>
                </td>
                <td class="px-5 py-4">
                  <div class="flex justify-end gap-2">
                    <button class="inline-flex h-9 w-9 items-center justify-center border border-line/70 bg-panelStrong/70 text-slate-200 transition hover:border-accent/60 hover:text-white" @click="viewSubmissions(form)" title="View submissions">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                    </button>
                    <button class="inline-flex h-9 w-9 items-center justify-center border border-line/70 bg-panelStrong/70 text-slate-200 transition hover:border-accent/60 hover:text-white" @click="openModal(form)" title="Edit">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                    </button>
                    <button class="inline-flex h-9 w-9 items-center justify-center border border-danger/40 bg-danger/10 text-rose-200 transition hover:border-danger hover:text-white" @click="deleteForm(form)" title="Delete">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3,6 5,6 21,6"/><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2"/></svg>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </main>

    <teleport to="body">
      <div v-if="showModal" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4" @click.self="closeModal">
        <div class="w-full max-w-xl animate-float-in border border-line/70 bg-ink shadow-soft">
          <div class="flex items-center justify-between border-b border-line/70 px-6 py-4">
            <h2 class="text-lg font-semibold">{{ editingForm ? 'Edit Form' : 'New Form' }}</h2>
            <button class="flex h-8 w-8 items-center justify-center text-slate-400 transition hover:bg-panel hover:text-white" @click="closeModal">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
          </div>
          <form @submit.prevent="saveForm">
            <div class="space-y-5 px-6 py-6">
              <div class="grid gap-4 md:grid-cols-2">
                <div>
                  <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Slug</label>
                  <input type="text" v-model="formData.slug" required placeholder="my-form" :disabled="editingForm" class="mt-2 w-full border border-line bg-slate-800 px-4 py-2.5 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40 disabled:opacity-60">
                  <div class="mt-2 text-xs text-slate-500">Lowercase, numbers, hyphens only</div>
                </div>
                <div>
                  <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Name</label>
                  <input type="text" v-model="formData.name" required placeholder="My Contact Form" class="mt-2 w-full border border-line bg-slate-800 px-4 py-2.5 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40">
                </div>
              </div>
              <div>
                <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Notification Email</label>
                <input type="email" v-model="formData.notifyEmail" placeholder="team@example.com" class="mt-2 w-full border border-line bg-slate-800 px-4 py-2.5 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40">
                <div class="mt-2 text-xs text-slate-500">Receive email on new submissions</div>
              </div>
              <div>
                <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Redirect URL</label>
                <input type="url" v-model="formData.redirectUrl" placeholder="https://example.com/thank-you" class="mt-2 w-full border border-line bg-slate-800 px-4 py-2.5 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40">
                <div class="mt-2 text-xs text-slate-500">Redirect after HTML form submission</div>
              </div>
              <div>
                <label class="text-xs font-semibold uppercase tracking-[0.2em] text-slate-400">Allowed Origins</label>
                <input type="text" v-model="formData.allowedOrigins" placeholder="https://example.com, https://app.example.com" class="mt-2 w-full border border-line bg-slate-800 px-4 py-2.5 text-sm text-white placeholder-slate-500 caret-white focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/40">
                <div class="mt-2 text-xs text-slate-500">Comma-separated domains (leave empty to allow all)</div>
              </div>
            </div>
            <div class="flex items-center justify-end gap-3 border-t border-line/70 px-6 py-4">
              <button type="button" class="border border-line/70 bg-panelStrong/70 px-4 py-2 text-sm font-semibold text-slate-200 transition hover:border-accent/60 hover:text-white" @click="closeModal">Cancel</button>
              <button type="submit" class="bg-accent px-4 py-2 text-sm font-semibold text-ink shadow-soft transition hover:bg-accentSoft disabled:opacity-60" :disabled="saving">{{ saving ? 'Saving...' : 'Save Form' }}</button>
            </div>
          </form>
        </div>
      </div>
    </teleport>

    <teleport to="body">
      <div v-if="showSubmissions" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4" @click.self="closeSubmissions">
        <div class="w-full max-w-4xl animate-float-in border border-line/70 bg-ink shadow-soft">
          <div class="flex items-center justify-between border-b border-line/70 px-6 py-4">
            <div>
              <h2 class="text-lg font-semibold">{{ selectedForm?.name }}</h2>
              <div class="text-xs text-slate-400">{{ submissions.length }} submission{{ submissions.length !== 1 ? 's' : '' }}</div>
            </div>
            <button class="flex h-8 w-8 items-center justify-center text-slate-400 transition hover:bg-panel hover:text-white" @click="closeSubmissions">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
            </button>
          </div>
          <div v-if="submissions.length === 0" class="px-6 py-16 text-center">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" class="mx-auto text-slate-600"><polyline points="22,12 16,12 14,15 10,15 8,12 2,12"/><path d="M5.45 5.11L2 12v6a2 2 0 002 2h16a2 2 0 002-2v-6l-3.45-6.89A2 2 0 0016.76 4H7.24a2 2 0 00-1.79 1.11z"/></svg>
            <p class="mt-3 text-sm text-slate-400">No submissions yet</p>
          </div>
          <div v-else class="max-h-[70vh] overflow-y-auto">
            <table class="w-full text-left text-sm">
              <thead class="sticky top-0 bg-panelStrong text-xs uppercase tracking-[0.3em] text-slate-400">
                <tr>
                  <th class="px-5 py-3 font-semibold">Date</th>
                  <th class="px-5 py-3 font-semibold">Data</th>
                  <th class="px-5 py-3 font-semibold">IP</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="sub in submissions" :key="sub.id" class="border-b border-line/60">
                  <td class="whitespace-nowrap px-5 py-3 align-top text-xs text-slate-400">{{ formatDate(sub.createdAt) }}</td>
                  <td class="px-5 py-3">
                    <div class="space-y-1">
                      <div v-for="(val, key) in sub.data" :key="key" class="flex items-baseline gap-2 text-sm">
                        <span class="shrink-0 font-mono text-xs text-slate-500">{{ key }}</span>
                        <span class="text-slate-200">{{ typeof val === 'object' ? JSON.stringify(val) : val }}</span>
                      </div>
                    </div>
                  </td>
                  <td class="whitespace-nowrap px-5 py-3 align-top font-mono text-xs text-slate-400">{{ sub.ip || '-' }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </teleport>

    <teleport to="body">
      <div v-if="showDeleteConfirm" class="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm px-4" @click.self="cancelDelete">
        <div class="w-full max-w-sm animate-float-in border border-line/70 bg-ink shadow-soft">
          <div class="px-6 py-6 text-center">
            <div class="mx-auto flex h-12 w-12 items-center justify-center bg-danger/15">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-danger"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            </div>
            <h3 class="mt-4 text-lg font-semibold">Delete form</h3>
            <p class="mt-2 text-sm text-slate-400">Delete <span class="font-semibold text-slate-200">"{{ formToDelete?.name }}"</span> and all its submissions? This cannot be undone.</p>
          </div>
          <div class="flex gap-3 border-t border-line/70 px-6 py-4">
            <button class="flex-1 border border-line/70 bg-panelStrong/70 px-4 py-2.5 text-sm font-semibold text-slate-200 transition hover:border-accent/60 hover:text-white" @click="cancelDelete">Cancel</button>
            <button class="flex-1 bg-danger px-4 py-2.5 text-sm font-semibold text-white shadow-soft transition hover:bg-rose-400" @click="confirmDelete">Delete</button>
          </div>
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
        const showDeleteConfirm = ref(false);
        const formToDelete = ref(null);

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

        const deleteForm = (form) => {
          formToDelete.value = form;
          showDeleteConfirm.value = true;
        };

        const confirmDelete = async () => {
          const form = formToDelete.value;
          showDeleteConfirm.value = false;
          formToDelete.value = null;
          if (!form) return;
          try {
            const res = await fetch('/admin/api/forms/' + form.slug, { method: 'DELETE' });
            if (res.status === 401) return window.location.href = '/admin/login';
            if (res.ok) { showAlert('Form deleted'); loadForms(); }
            else showAlert('Failed to delete', 'error');
          } catch (e) { showAlert('Network error', 'error'); }
        };

        const cancelDelete = () => {
          showDeleteConfirm.value = false;
          formToDelete.value = null;
        };

        const copyEndpoint = async (slug) => {
          const url = window.location.origin + '/api/f/' + slug;
          try {
            await navigator.clipboard.writeText(url);
            showAlert('Endpoint URL copied');
          } catch (e) { showAlert('Failed to copy', 'error'); }
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

        onMounted(() => {
          loadForms();
          document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
              if (showDeleteConfirm.value) cancelDelete();
              else if (showSubmissions.value) closeSubmissions();
              else if (showModal.value) closeModal();
            }
          });
        });

        return { forms, alert, showModal, showSubmissions, editingForm, selectedForm, submissions, saving, formData, showDeleteConfirm, formToDelete, totalSubmissions, showAlert, openModal, closeModal, saveForm, deleteForm, confirmDelete, cancelDelete, copyEndpoint, viewSubmissions, closeSubmissions, formatDate };
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
