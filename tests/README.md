# Contact delivery tests

Run `TEST_SMTP_HOST=127.0.0.1 TEST_MAILHOG_URL=http://127.0.0.1:8026 node --test tests/contact-http.test.mjs` with a local Mailhog SMTP listener on port 1026.

Tests create temporary databases and send only to Mailhog. Form creation and submission use HTTP. Cloudflare response fixtures are copied from https://developers.cloudflare.com/turnstile/troubleshooting/testing/#validation-response. The success fixture has action `test`, so positive cases use that protected form slug; contact and demo slugs exercise action mismatch rejection. These fixtures do not establish that production keys or DNS are configured.
