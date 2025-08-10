# Verify LTI Tool

This project provides a Flask based [LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3/) application that exposes a minimal file
manager together with [Dynamic Registration](https://www.imsglobal.org/spec/lti-dynamic/v1p0/) so learning management systems
(LMSs) can install the tool without manual key exchange. Files are stored on the application server for further processing or
transfer to another storage facility.

## Features

- OIDC login and LTI 1.3 launch endpoints.
- Dynamic Registration so admins only need a single URL.
- Deep linking to allow teachers to choose resources at placement time.
- JWKS and tool configuration endpoints to simplify external tool setup.
- Simple file browser for testing and legacy workflows.

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt`.

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Configuration

Key environment variables:

- `DATABASE_URL` – PostgreSQL URL provided by Railway (required).
- `APP_BASE_URL` – External base URL of the deployed app.
- `TOOL_TITLE`, `TOOL_DESCRIPTION`, `TOOL_CONTACT_EMAIL` – Metadata displayed to LMS admins.
- `DEEP_LINK_RETURN_URL` – Optional fallback for the deep-link return endpoint (normally
  provided by the launch claim).
- `SECRET_KEY` – Flask session secret.

File uploads are stored in `/tmp/lti_files`; adjust `UPLOAD_FOLDER` if a different location is needed.

## Running the Tool

```bash
python app.py
```

By default the server listens on port `5000`.

## Dynamic Registration

Dynamic Registration lets an LMS discover the tool configuration and key set automatically.

1. Deploy the server with `APP_BASE_URL` set to the externally reachable URL (e.g. the Railway URL).
2. Visit `https://<APP_BASE_URL>/lti/dynamic-registration` to copy the Registration URL.
3. Paste this URL into the LMS's "Dynamic Registration" or "Registration URL" field.
4. The LMS will call the URL with the required parameters. The tool will register itself and show a success page listing the
   new platform. Teachers can then add the tool to courses via deep linking.

The tool also exposes:

- `https://<APP_BASE_URL>/.well-known/tool-configuration` – metadata describing the tool.
- `https://<APP_BASE_URL>/.well-known/jwks.json` – public keys for JWT signature verification.

## API Endpoints

- `GET /.well-known/tool-configuration` – JSON metadata for Dynamic Registration.
- `GET /.well-known/jwks.json` – public keys for verifying JWTs.
- `GET /files` – basic file browser UI.
- `GET /list_uploaded_files` – JSON list of files stored on the server.

## Development & Debugging

Useful helper routes:

- `GET /debug_routes` – list all registered routes.
- `GET /health` – basic health check.

## Notes

This implementation stores files and session metadata in memory and the filesystem. For production deployments, integrate with persistent storage and secure session management.
