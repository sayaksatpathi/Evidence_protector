
  # Evidence Protector Web UI

  This is a code bundle for Evidence Protector Web UI. The original project is available at https://www.figma.com/design/w3NdjP8aqV7SYnvxB0hKVw/Evidence-Protector-Web-UI.

  ## Running the code

  This UI expects the Python API server to be running at `http://127.0.0.1:8000`.
  The dev server proxies `/api/*` to the backend (see `vite.config.ts`).

  From the repo root, start the backend:

  ```powershell
  & ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt
  & ".\.venv\Scripts\python.exe" -m uvicorn evidence_protector_api:app --reload --host 127.0.0.1 --port 8000
  ```

  Run `npm i` to install the dependencies.

  Run `npm run dev` to start the development server.
  