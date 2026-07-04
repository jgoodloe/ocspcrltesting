import { useEffect, useState } from 'react';
import { ConfirmDialog } from '../components/ConfirmDialog';
import {
  ApiError,
  deleteCACert,
  fetchCACert,
  listCACerts,
  listWellKnownCAs,
  uploadCACert,
  type CACert,
  type CACertImportResult,
  type WellKnownCA,
} from '../lib/api';
import { formatDateTime } from '../lib/format';

/**
 * Saved CA certificate library: store commonly used roots and issuing CAs
 * (Federal Common Policy, agency SSP CAs, lab CAs) once, then pick them on
 * the New Run form instead of hunting for the right file every time.
 */
export function CALibrary() {
  const [certs, setCerts] = useState<CACert[] | null>(null);
  const [wellKnown, setWellKnown] = useState<WellKnownCA[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [uploadName, setUploadName] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [fetchUrl, setFetchUrl] = useState('');
  const [fetchName, setFetchName] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<CACert | null>(null);
  const [fileKey, setFileKey] = useState(0);

  const load = async () => {
    try {
      const res = await listCACerts();
      setCerts(res.items);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not reach the API.');
    }
  };

  useEffect(() => {
    void load();
    listWellKnownCAs()
      .then((res) => setWellKnown(res.items))
      .catch(() => {
        /* optional */
      });
  }, []);

  const describeImport = (result: CACertImportResult): string => {
    const created = result.created.length;
    const dup = result.skipped_duplicates;
    if (created === 0 && dup > 0) return 'Already in the library — no new certificates added.';
    const names = result.created.map((c) => c.name).slice(0, 4).join(', ');
    return `Added ${created} certificate${created === 1 ? '' : 's'} (${names}${created > 4 ? ', …' : ''})${dup ? `; ${dup} duplicate${dup === 1 ? '' : 's'} skipped` : ''}.`;
  };

  const runImport = async (label: string, action: () => Promise<CACertImportResult>) => {
    setBusy(label);
    setError(null);
    setNotice(null);
    try {
      const result = await action();
      setNotice(describeImport(result));
      await load();
      return true;
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Import failed.');
      return false;
    } finally {
      setBusy(null);
    }
  };

  const handleUpload = async () => {
    if (!uploadFile) {
      setError('Choose a certificate file to upload.');
      return;
    }
    const ok = await runImport('upload', () =>
      uploadCACert(uploadFile, uploadName.trim() || undefined),
    );
    if (ok) {
      setUploadFile(null);
      setUploadName('');
      setFileKey((k) => k + 1);
    }
  };

  const handleFetch = async () => {
    if (!fetchUrl.trim()) {
      setError('Enter the certificate URL to fetch.');
      return;
    }
    const ok = await runImport('fetch', () =>
      fetchCACert(fetchUrl.trim(), fetchName.trim() || undefined),
    );
    if (ok) {
      setFetchUrl('');
      setFetchName('');
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteCACert(pendingDelete.id);
      setPendingDelete(null);
      void load();
    } catch (err) {
      setPendingDelete(null);
      setError(err instanceof ApiError ? err.detail : 'Delete failed.');
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">CA Library</h1>
          <p className="page-subtitle">
            Save commonly used root and issuing CA certificates once, then pick them on the New
            Run form instead of uploading files each time.
          </p>
        </div>
      </div>

      {error && (
        <div className="form-error" role="alert">
          <span className="err-status">Error</span>
          {error}
        </div>
      )}
      {notice && (
        <div className="panel notice-ok" role="status" style={{ marginBottom: 14 }}>
          {notice}
        </div>
      )}

      <div className="panel">
        <h2 className="section-label">Add certificates</h2>
        <div className="ca-add-grid">
          <div>
            <h3 className="section-label" style={{ fontSize: 10 }}>
              Upload a file
            </h3>
            <div className="field">
              <label className="field-label" htmlFor="ca-upload-file">
                Certificate file (PEM, DER, PEM bundle, or PKCS#7 .p7c/.p7b)
              </label>
              <input
                id="ca-upload-file"
                key={fileKey}
                className="file-input"
                type="file"
                accept=".pem,.crt,.cer,.der,.p7c,.p7b"
                onChange={(e) => setUploadFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ca-upload-name">
                Display name (optional, single certificate only)
              </label>
              <input
                id="ca-upload-name"
                className="input"
                placeholder="e.g. Lab Root CA"
                value={uploadName}
                onChange={(e) => setUploadName(e.target.value)}
              />
            </div>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy !== null}
              onClick={() => void handleUpload()}
            >
              {busy === 'upload' ? 'Uploading…' : 'Add to library'}
            </button>
          </div>
          <div>
            <h3 className="section-label" style={{ fontSize: 10 }}>
              Fetch from a URL
            </h3>
            <div className="field">
              <label className="field-label" htmlFor="ca-fetch-url">
                Certificate URL (the server downloads and validates it)
              </label>
              <input
                id="ca-fetch-url"
                className="input mono"
                type="url"
                placeholder="http://repo.fpki.gov/fcpca/fcpcag2.crt"
                value={fetchUrl}
                onChange={(e) => setFetchUrl(e.target.value)}
              />
            </div>
            <div className="field">
              <label className="field-label" htmlFor="ca-fetch-name">
                Display name (optional, single certificate only)
              </label>
              <input
                id="ca-fetch-name"
                className="input"
                value={fetchName}
                onChange={(e) => setFetchName(e.target.value)}
              />
            </div>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy !== null}
              onClick={() => void handleFetch()}
            >
              {busy === 'fetch' ? 'Fetching…' : 'Fetch and add'}
            </button>
          </div>
        </div>

        {wellKnown.length > 0 && (
          <>
            <h3 className="section-label" style={{ marginTop: 18 }}>
              Well-known Federal PKI CAs
            </h3>
            <ul className="wellknown-list">
              {wellKnown.map((w) => (
                <li key={w.key} className="wellknown-item">
                  <div>
                    <span style={{ fontWeight: 600 }}>{w.name}</span>
                    <span className="faint" style={{ marginLeft: 8, fontSize: 12 }}>
                      {w.description}
                    </span>
                    <div className="faint mono" style={{ fontSize: 11 }}>
                      {w.url}
                    </div>
                  </div>
                  <button
                    type="button"
                    className="btn btn-sm"
                    disabled={busy !== null}
                    onClick={() => void runImport(w.key, () => fetchCACert(w.url, w.name))}
                  >
                    {busy === w.key ? 'Importing…' : 'Import'}
                  </button>
                </li>
              ))}
            </ul>
          </>
        )}
      </div>

      <div className="panel">
        <h2 className="section-label">Saved certificates</h2>
        {certs === null ? (
          <div className="loading">Loading…</div>
        ) : certs.length === 0 ? (
          <div className="table-empty">
            No saved certificates yet. Upload one, fetch by URL, or import a well-known Federal
            PKI CA above.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Subject</th>
                  <th scope="col">Expires</th>
                  <th scope="col">Type</th>
                  <th scope="col">Source</th>
                  <th scope="col" aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {certs.map((c) => (
                  <tr key={c.id}>
                    <td style={{ fontWeight: 600 }}>{c.name}</td>
                    <td className="mono truncate" title={c.subject}>
                      {c.subject}
                    </td>
                    <td className="nowrap muted">
                      {formatDateTime(c.not_after)}
                      {c.expired && (
                        <span className="pill FAIL" style={{ marginLeft: 6 }}>
                          <span className="pill-icon" aria-hidden="true">
                            !
                          </span>
                          expired
                        </span>
                      )}
                    </td>
                    <td className="nowrap muted">
                      {c.self_signed ? 'Root (self-signed)' : c.is_ca ? 'CA' : 'Leaf'}
                    </td>
                    <td className="nowrap muted" title={c.source_url ?? undefined}>
                      {c.source}
                    </td>
                    <td className="nowrap" style={{ textAlign: 'right' }}>
                      <button
                        type="button"
                        className="btn btn-ghost btn-sm"
                        onClick={() => setPendingDelete(c)}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {pendingDelete && (
        <ConfirmDialog
          title="Remove this certificate from the library?"
          confirmLabel="Remove"
          danger
          onConfirm={() => void handleDelete()}
          onCancel={() => setPendingDelete(null)}
        >
          {`Removes “${pendingDelete.name}” from the CA library. Existing runs are not affected, but profiles referencing it will need a new selection.`}
        </ConfirmDialog>
      )}
    </>
  );
}
