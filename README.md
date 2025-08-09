# LTI File Manager for Moodle

This project provides a Flask-based [LTI 1.3](https://www.imsglobal.org/spec/lti/v1p3/) tool that lets Moodle administrators browse and copy learner files from a course and upload new content to a server-side storage location. Files are stored on the application server for further processing or transfer to another storage facility.

## Features

- OIDC login and LTI 1.3 launch endpoints for secure integration with Moodle.
- REST API helpers for calling Moodle's web services.
- Copy learner files from Moodle into a local upload directory.
- Upload new files from the browser to the server.
- JWKS and tool configuration endpoints to simplify external tool setup.
- Lightweight in-memory metadata store (replace with a database in production).

## Requirements

- Python 3.10+
- Dependencies listed in `requirements.txt` (`Flask`, `PyJWT`, `cryptography`, `requests`, `Werkzeug`).

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Configuration

The application is configured through environment variables:

- `SECRET_KEY` – Flask session secret.
- `LTI_CLIENT_ID`, `LTI_DEPLOYMENT_ID`, `LTI_ISSUER`, `LTI_AUTH_LOGIN_URL`, `LTI_AUTH_TOKEN_URL`, `LTI_KEY_SET_URL` – LTI 1.3 platform details from Moodle.
- `MOODLE_URL`, `MOODLE_API_TOKEN`, `MOODLE_SERVICE` – Moodle REST API settings.
- `PRIVATE_KEY_PEM`/`PUBLIC_KEY_PEM` or `PRIVATE_KEY_B64`/`PUBLIC_KEY_B64` – RSA keys for signing JWTs. If not supplied, a key pair is generated at startup.

File uploads are stored in `/tmp/lti_files`; adjust `UPLOAD_FOLDER` in `app.py` for a persistent storage location.

## Running the Tool

```bash
python app.py
```

By default the server listens on port `5000`.

## Moodle Integration

1. Deploy the server so Moodle can reach it.
2. In Moodle, create an LTI 1.3 external tool and provide the URL `https://<your-tool-domain>/config.json` to import configuration automatically.
3. Complete the external tool setup using the generated public key endpoint at `https://<your-tool-domain>/.well-known/jwks.json`.
4. Launch the tool from a course. Administrators will see a file browser where they can:
   - Retrieve a learner's existing Moodle files.
   - Copy selected Moodle files into the tool's upload directory.
   - Upload new files from their local machine.

Uploaded or copied files can be inspected at `https://<your-tool-domain>/files` or via the JSON API at `/list_uploaded_files`.

## API Endpoints

- `GET /get_user_files/<user_id>?course_id=<course>` – fetch a learner's Moodle files.
- `POST /copy_moodle_files` – copy selected Moodle files into the upload directory.
- `POST /upload_files` – upload new files from the browser.
- `GET /download_file/<file_id>` – placeholder download endpoint.
- `DELETE /delete_file/<file_id>` – placeholder delete endpoint.
- `GET /list_uploaded_files` – JSON list of files stored on the server.
- `GET /.well-known/jwks.json` – public keys for Moodle to verify JWTs.
- `GET /config.json` – LTI tool configuration.

## Development & Debugging

Useful helper routes:

- `GET /test_session` – inspect session contents.
- `GET /test_moodle_api` – verify Moodle API connectivity.
- `GET /debug_routes` – list all registered routes.
- `GET /launch_test` – launch the interface with mock LTI data.
- `GET /health` – basic health check.

## Notes

This implementation stores files and session metadata in memory and the filesystem. For production deployments, integrate with persistent storage and secure session management.
