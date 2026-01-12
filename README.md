# FormSink

A simple, reusable form submission backend. Create form endpoints, collect submissions, and get email notifications.

## Features

- **SQLite storage** - Persistent database, no external dependencies
- **Admin UI** - Vue-powered web interface to manage forms and view submissions
- **Session-based auth** - Secure login with httpOnly cookies (no API keys in URLs)
- **Email notifications** - Get notified on new submissions via SMTP
- **Origin restrictions** - Limit which domains can submit to your forms
- **External API** - Optional API key for programmatic access

## Quick Start

```bash
# Install dependencies
npm install

# Start the server
npm run dev
```

Open `http://localhost:3001/admin` and login with password `admin` (default).

## Configuration

Copy `.env.example` to `.env` and configure:

```env
PORT=3001

# Admin login password
ADMIN_PASSWORD=your-secure-password

# External API key (optional)
API_KEY=your-api-key

# SMTP (optional)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=user@example.com
SMTP_PASS=password
SMTP_FROM=noreply@example.com
```

## Usage

### 1. Create a Form

Login to the admin UI at `/admin` and click "New Form", or use the API:

```bash
curl -X POST http://localhost:3001/api/forms \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "slug": "contact",
    "name": "Contact Form",
    "notifyEmail": "team@example.com",
    "allowedOrigins": ["https://example.com"]
  }'
```

### 2. Submit to Your Form

```javascript
fetch('https://forms.example.com/api/f/contact', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'John Doe',
    email: 'john@example.com',
    message: 'Hello!'
  })
});
```

Or with HTML:

```html
<form action="https://forms.example.com/api/f/contact" method="POST">
  <input name="name" required>
  <input name="email" type="email" required>
  <textarea name="message"></textarea>
  <button type="submit">Send</button>
</form>
```

### 3. View Submissions

Login to `/admin` and click "View Submissions" on any form.

## API Reference

### Admin UI (Session Auth)

| Endpoint | Description |
|----------|-------------|
| `GET /admin` | Admin dashboard |
| `GET /admin/login` | Login page |
| `POST /admin/login` | Authenticate |
| `POST /admin/logout` | Logout |

### External API (API Key in `X-API-Key` header)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/forms` | List all forms |
| `GET` | `/api/forms/:slug` | Get form details |
| `POST` | `/api/forms` | Create a form |
| `PUT` | `/api/forms/:slug` | Update a form |
| `DELETE` | `/api/forms/:slug` | Delete a form |
| `GET` | `/api/submissions/:slug` | List submissions |

### Public (No Auth)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/f/:slug` | Submit to a form |
| `GET` | `/health` | Health check |

## Form Options

| Field | Type | Description |
|-------|------|-------------|
| `slug` | string | URL-safe identifier (required) |
| `name` | string | Display name (required) |
| `notifyEmail` | string | Email for notifications |
| `redirectUrl` | string | Redirect after HTML form submit |
| `allowedOrigins` | string[] | Restrict submission origins |

## Security

- Admin UI uses session-based auth with httpOnly cookies
- Sessions expire after 24 hours
- External API requires `X-API-Key` header (not query params)
- CSRF protection via SameSite cookies

## Data Storage

Data is stored in `data/formsink.db` (SQLite). Back up this file to preserve your forms and submissions.

## License

MIT
