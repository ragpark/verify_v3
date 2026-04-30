# Moodle LMS Setup Guide for Verify LTI Tool

This guide is for **Moodle administrators** and **tool developers** setting up this Flask-based LTI 1.3 tool with Moodle.

## 1) Prerequisites

Before starting in Moodle, verify the tool deployment is ready:

- The tool is deployed at a public **HTTPS** URL (no HTTP).
- `APP_BASE_URL` matches the exact external URL of the tool.
- `.well-known` endpoints are reachable:
  - `https://<tool-host>/.well-known/tool-configuration`
  - `https://<tool-host>/.well-known/jwks.json`
- A persistent database is configured (`DATABASE_URL`) so platform/client/deployment registrations survive restarts.

Recommended environment variables:

- `APP_BASE_URL=https://<tool-host>`
- `SECRET_KEY=<strong-random-value>`
- `TOOL_TITLE`, `TOOL_DESCRIPTION`, `TOOL_CONTACT_EMAIL`
- `UPLOAD_FOLDER` (optional; defaults to `/tmp/lti_files`)

---

## 2) Moodle Admin Setup (Dynamic Registration)

Use this path when Moodle supports LTI Dynamic Registration in your environment.

1. In the tool admin page, copy the registration URL:
   - `https://<tool-host>/lti/dynamic-registration`
2. In Moodle, go to **Site administration → Plugins → External tool → Manage tools**.
3. Choose the option to add/configure a tool using a **Registration URL** (wording varies by Moodle version).
4. Paste the registration URL and submit.
5. Complete Moodle prompts/consent screens.
6. Confirm the tool appears in **Manage tools** and is enabled.
7. In a course, add an **External tool** activity and choose the newly registered tool.

If successful, Moodle should be able to initiate login at `/lti/login` and launch to `/lti/launch`.

---

## 3) Moodle Admin Setup (Manual LTI 1.3 fallback)

If dynamic registration is unavailable or blocked by policy, configure manually.

In Moodle's external tool configuration:

- **Tool URL / Launch URL**: `https://<tool-host>/lti/launch`
- **Initiate login URL**: `https://<tool-host>/lti/login`
- **Public keyset URL (JWKS)**: `https://<tool-host>/.well-known/jwks.json`
- **Redirection URI(s)**: include `https://<tool-host>/lti/launch`

After saving, record Moodle-generated values (client ID, issuer, deployment ID) and ensure the tool has a matching `Platform`/`Deployment` record (via registration flow or direct DB seeding in controlled environments).

---

## 4) Course-level Instructor Setup

1. Open the target Moodle course.
2. Turn editing on.
3. Add an **External tool** activity.
4. Select the Verify tool.
5. Save and launch.

For deep-linking placements, initiate content selection from the external tool activity and select the appropriate resource in the tool UI.

---

## 5) Developer Notes: Required Adaptations / Hard-Coded Behavior

These are implementation details you should account for before production rollout.

### A. HTTPS is mandatory

- Registration payload generation enforces `APP_BASE_URL` starting with `https://`.
- Non-HTTPS values are rejected with HTTP 400 during tool configuration requests.

### B. Cookie policy for iframe launches

The app currently hard-codes iframe-compatible cookie settings:

- `SESSION_COOKIE_SECURE = True`
- `SESSION_COOKIE_SAMESITE = "None"`
- `SESSION_COOKIE_HTTPONLY = True`
- `SESSION_COOKIE_NAME = "verifyv3_session"`

Keep TLS enabled end-to-end, or logins from Moodle iframes will fail.

### C. Tool metadata defaults are hard coded

If not overridden by environment variables, defaults are used:

- `TOOL_TITLE="Verify"`
- `TOOL_DESCRIPTION="LTI Tool"`
- `TOOL_CONTACT_EMAIL="support@example.com"`

Set these explicitly for your tenant/organization.

### D. Deep-link return behavior

- Deep link return URL is read from launch claims and stored in session.
- A fallback `DEEP_LINK_RETURN_URL` exists, but production behavior should rely on claim-provided values from Moodle.

### E. File storage is local filesystem by default

- Uploads default to `/tmp/lti_files`.
- In containerized or autoscaled environments, local `/tmp` is ephemeral.
- For production, switch to persistent/object storage and add retention/security controls.

### F. Moodle API integration expectations

- The app exposes `MOODLE_URL` and `MOODLE_API_TOKEN` configuration points.
- Ensure these are set only if you are enabling Moodle web-service calls and that the token has minimum required permissions.

### G. Operational cleanup before production

- Remove or downgrade verbose login/launch debug logging in `app/lti/launch.py` to avoid sensitive data in logs.
- Keep `SECRET_KEY` strong and rotated per environment.
- Replace in-memory/test DB defaults with a managed PostgreSQL (or equivalent) instance.

---

## 6) Validation Checklist

After setup, verify:

- Tool config endpoint returns JSON: `/.well-known/tool-configuration`
- JWKS endpoint returns keys: `/.well-known/jwks.json`
- Moodle can create launches without `invalid state`/`invalid nonce` errors
- Course launch reaches the expected tool landing flow
- Deep-link launches return content selections correctly
- Uploaded files appear in `/files` and `GET /list_uploaded_files`

---

## 7) Troubleshooting Quick Reference

- **HTTP 400 from tool configuration**: `APP_BASE_URL` is not HTTPS.
- **Launch loop or failed login**: verify login URL `/lti/login`, launch URL `/lti/launch`, and cookie settings.
- **Unknown platform issuer**: platform not registered (or stale DB); repeat registration and verify issuer/client ID.
- **Missing files after restart**: using ephemeral local storage (`/tmp/lti_files`); move to persistent storage.

