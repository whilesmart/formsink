import Database from 'better-sqlite3';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '../data');

if (!existsSync(DATA_DIR)) {
  mkdirSync(DATA_DIR, { recursive: true });
}

const db = new Database(join(DATA_DIR, 'formsink.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS forms (
    slug TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    notify_email TEXT,
    redirect_url TEXT,
    allowed_origins TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT
  );

  CREATE TABLE IF NOT EXISTS submissions (
    id TEXT PRIMARY KEY,
    form_slug TEXT NOT NULL,
    data TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (form_slug) REFERENCES forms(slug) ON DELETE CASCADE
  );

  CREATE INDEX IF NOT EXISTS idx_submissions_form_slug ON submissions(form_slug);
  CREATE INDEX IF NOT EXISTS idx_submissions_created_at ON submissions(created_at);
`);

export const forms = {
  create(form) {
    const stmt = db.prepare(`
      INSERT INTO forms (slug, name, notify_email, redirect_url, allowed_origins)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(
      form.slug,
      form.name,
      form.notifyEmail || null,
      form.redirectUrl || null,
      JSON.stringify(form.allowedOrigins || [])
    );
    return this.get(form.slug);
  },

  update(slug, data) {
    const form = this.get(slug);
    if (!form) return null;

    const stmt = db.prepare(`
      UPDATE forms SET
        name = ?,
        notify_email = ?,
        redirect_url = ?,
        allowed_origins = ?,
        updated_at = datetime('now')
      WHERE slug = ?
    `);
    stmt.run(
      data.name ?? form.name,
      data.notifyEmail ?? form.notifyEmail,
      data.redirectUrl ?? form.redirectUrl,
      JSON.stringify(data.allowedOrigins ?? form.allowedOrigins),
      slug
    );
    return this.get(slug);
  },

  delete(slug) {
    const stmt = db.prepare('DELETE FROM forms WHERE slug = ?');
    return stmt.run(slug).changes > 0;
  },

  get(slug) {
    const stmt = db.prepare('SELECT * FROM forms WHERE slug = ?');
    const row = stmt.get(slug);
    return row ? this._mapRow(row) : null;
  },

  list() {
    const stmt = db.prepare('SELECT * FROM forms ORDER BY created_at DESC');
    return stmt.all().map(this._mapRow);
  },

  _mapRow(row) {
    return {
      slug: row.slug,
      name: row.name,
      notifyEmail: row.notify_email,
      redirectUrl: row.redirect_url,
      allowedOrigins: JSON.parse(row.allowed_origins || '[]'),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  },
};

export const submissions = {
  create(submission) {
    const stmt = db.prepare(`
      INSERT INTO submissions (id, form_slug, data, ip, user_agent)
      VALUES (?, ?, ?, ?, ?)
    `);
    stmt.run(
      submission.id,
      submission.formSlug,
      JSON.stringify(submission.data),
      submission.ip || null,
      submission.userAgent || null
    );
    return this.get(submission.id);
  },

  get(id) {
    const stmt = db.prepare('SELECT * FROM submissions WHERE id = ?');
    const row = stmt.get(id);
    return row ? this._mapRow(row) : null;
  },

  listByForm(formSlug, { limit = 100, offset = 0 } = {}) {
    const stmt = db.prepare(`
      SELECT * FROM submissions
      WHERE form_slug = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `);
    return stmt.all(formSlug, limit, offset).map(this._mapRow);
  },

  countByForm(formSlug) {
    const stmt = db.prepare('SELECT COUNT(*) as count FROM submissions WHERE form_slug = ?');
    return stmt.get(formSlug).count;
  },

  delete(id) {
    const stmt = db.prepare('DELETE FROM submissions WHERE id = ?');
    return stmt.run(id).changes > 0;
  },

  deleteByForm(formSlug) {
    const stmt = db.prepare('DELETE FROM submissions WHERE form_slug = ?');
    return stmt.run(formSlug).changes;
  },

  _mapRow(row) {
    return {
      id: row.id,
      formSlug: row.form_slug,
      data: JSON.parse(row.data),
      ip: row.ip,
      userAgent: row.user_agent,
      createdAt: row.created_at,
    };
  },
};

export default db;
