import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { ConfigFields } from '../components/ConfigFields';
import { FileField } from '../components/FileField';
import {
  ApiError,
  createProfile,
  createRun,
  defaultRunConfig,
  listProfiles,
  type Profile,
  type RunConfig,
} from '../lib/api';

interface FileState {
  issuer_cert: File | null;
  good_cert: File | null;
  revoked_cert: File | null;
  unknown_ca_cert: File | null;
  trust_anchor: File | null;
  client_cert: File | null;
  client_key: File | null;
}

const EMPTY_FILES: FileState = {
  issuer_cert: null,
  good_cert: null,
  revoked_cert: null,
  unknown_ca_cert: null,
  trust_anchor: null,
  client_cert: null,
  client_key: null,
};

/** Merge a saved profile config over the defaults, tagging provenance. */
function configFromProfile(profile: Profile): RunConfig {
  return {
    ...defaultRunConfig(),
    ...profile.config,
    categories: { ...defaultRunConfig().categories, ...profile.config.categories },
    profile_id: profile.id,
  };
}

export function NewRun() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [config, setConfig] = useState<RunConfig>(defaultRunConfig);
  const [files, setFiles] = useState<FileState>(EMPTY_FILES);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [selectedProfile, setSelectedProfile] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<{ status?: number; detail: string } | null>(null);
  const [saveOpen, setSaveOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveDesc, setSaveDesc] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveDone, setSaveDone] = useState<string | null>(null);
  // Bumped on "Reset form" to remount the file pickers (clears native inputs
  // and their inspection cards).
  const [resetKey, setResetKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    listProfiles()
      .then((res) => {
        if (cancelled) return;
        setProfiles(res.items);
        // Preload from /runs/new?profile=ID
        const wanted = searchParams.get('profile');
        if (wanted) {
          const profile = res.items.find((p) => String(p.id) === wanted);
          if (profile) {
            setConfig(configFromProfile(profile));
            setSelectedProfile(String(profile.id));
          }
        }
      })
      .catch(() => {
        /* profiles are optional for this page */
      });
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const loadProfile = (id: string) => {
    setSelectedProfile(id);
    if (!id) return;
    const profile = profiles.find((p) => String(p.id) === id);
    if (profile) setConfig(configFromProfile(profile));
  };

  const setFile = (key: keyof FileState) => (file: File | null) =>
    setFiles((prev) => ({ ...prev, [key]: file }));

  const handleSaveProfile = async () => {
    setSaveError(null);
    if (!saveName.trim()) {
      setSaveError('Profile name is required.');
      return;
    }
    try {
      const { profile_id: _omit, ...configWithoutProvenance } = config;
      const created = await createProfile({
        name: saveName.trim(),
        description: saveDesc.trim() || null,
        config: configWithoutProvenance as RunConfig,
      });
      setProfiles((prev) => [...prev, created]);
      setSaveOpen(false);
      setSaveName('');
      setSaveDesc('');
      setSaveDone(`Saved profile “${created.name}”.`);
    } catch (err) {
      setSaveError(err instanceof ApiError ? err.detail : 'Could not save profile.');
    }
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!config.ocsp_url.trim()) {
      setError({ detail: 'OCSP responder URL is required.' });
      return;
    }
    if (!files.issuer_cert) {
      setError({ detail: 'Issuer certificate is required.' });
      return;
    }
    setSubmitting(true);
    try {
      const payload: RunConfig = {
        ...config,
        name: config.name?.trim() || null,
        ocsp_url: config.ocsp_url.trim(),
        crl_urls: config.crl_urls.map((u) => u.trim()).filter(Boolean),
      };
      const run = await createRun(payload, {
        issuer_cert: files.issuer_cert,
        good_cert: files.good_cert,
        revoked_cert: files.revoked_cert,
        unknown_ca_cert: files.unknown_ca_cert,
        trust_anchor: files.trust_anchor,
        client_cert: files.client_cert,
        client_key: files.client_key,
      });
      navigate(`/runs/${run.id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        setError({ status: err.status, detail: err.detail });
      } else {
        setError({ detail: 'Network error — could not reach the API.' });
      }
      setSubmitting(false);
    }
  };

  const errorPrefix = (status?: number): string => {
    if (status === 403) return 'Blocked by SSRF policy';
    if (status === 400) return 'Invalid config or certificate';
    if (status === 413) return 'Upload too large';
    if (status === 429) return 'Too many concurrent runs';
    if (status) return `Error ${status}`;
    return 'Error';
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">New test run</h1>
          <p className="page-subtitle">
            Configure the responder, upload certificates, and start testing.
          </p>
        </div>
        <div className="toolbar">
          <select
            className="select"
            value={selectedProfile}
            onChange={(e) => loadProfile(e.target.value)}
            aria-label="Load from profile"
          >
            <option value="">Load from profile…</option>
            {profiles.map((p) => (
              <option key={p.id} value={String(p.id)}>
                {p.name}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn"
            onClick={() => {
              setSaveOpen(true);
              setSaveDone(null);
            }}
          >
            Save as profile
          </button>
        </div>
      </div>

      {saveDone && (
        <div className="panel" style={{ marginBottom: 14, color: 'var(--pass)' }}>
          {saveDone}
        </div>
      )}

      {saveOpen && (
        <div className="dialog-backdrop" onMouseDown={() => setSaveOpen(false)}>
          <div
            className="dialog"
            role="dialog"
            aria-modal="true"
            aria-label="Save as profile"
            onMouseDown={(e) => e.stopPropagation()}
          >
            <h3>Save as profile</h3>
            {saveError && (
              <div className="form-error">
                <span className="err-status">Error</span>
                {saveError}
              </div>
            )}
            <div className="field">
              <span className="field-label">
                Name<span className="req">*</span>
              </span>
              <input
                className="input"
                autoFocus
                value={saveName}
                onChange={(e) => setSaveName(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') void handleSaveProfile();
                }}
              />
            </div>
            <div className="field">
              <span className="field-label">Description</span>
              <input
                className="input"
                value={saveDesc}
                onChange={(e) => setSaveDesc(e.target.value)}
              />
            </div>
            <div className="dialog-actions">
              <button type="button" className="btn" onClick={() => setSaveOpen(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void handleSaveProfile()}
              >
                Save profile
              </button>
            </div>
          </div>
        </div>
      )}

      <form onSubmit={(e) => void handleSubmit(e)} noValidate>
        {error && (
          <div className="form-error" role="alert">
            <span className="err-status">{errorPrefix(error.status)}</span>
            {error.detail}
          </div>
        )}

        <div className="panel">
          <div className="field">
            <span className="field-label">Run name</span>
            <input
              className="input"
              placeholder="optional label, e.g. nightly lab check"
              value={config.name ?? ''}
              onChange={(e) => setConfig({ ...config, name: e.target.value })}
            />
          </div>
          <ConfigFields config={config} onChange={setConfig} />
        </div>

        <div className="panel">
          <h3 className="section-label">Certificates</h3>
          <div className="file-grid" key={resetKey}>
            <FileField
              label="Issuer certificate"
              required
              hint="CA that issued the certificates under test (PEM or DER)"
              file={files.issuer_cert}
              onChange={setFile('issuer_cert')}
            />
            <FileField
              label="Known-good certificate"
              hint="leaf expected to be reported as good"
              file={files.good_cert}
              onChange={setFile('good_cert')}
            />
            <FileField
              label="Known-revoked certificate"
              hint="leaf expected to be reported as revoked"
              file={files.revoked_cert}
              onChange={setFile('revoked_cert')}
            />
            <FileField
              label="Unknown-CA certificate"
              hint="cert from a CA unknown to the responder"
              file={files.unknown_ca_cert}
              onChange={setFile('unknown_ca_cert')}
            />
            <FileField
              label="Trust anchor / intermediate chain"
              hint="PEM, may contain multiple certificates"
              file={files.trust_anchor}
              onChange={setFile('trust_anchor')}
            />
            <FileField
              label="Client TLS certificate"
              hint="for mutually-authenticated responders (PEM)"
              file={files.client_cert}
              onChange={setFile('client_cert')}
            />
            <FileField
              label="Client TLS key"
              sensitive
              hint="private key (PEM); never inspected or logged"
              file={files.client_key}
              onChange={setFile('client_key')}
            />
          </div>
        </div>

        <div className="toolbar" style={{ marginTop: 16 }}>
          <button type="submit" className="btn btn-primary" disabled={submitting}>
            {submitting ? 'Starting run…' : 'Start test run'}
          </button>
          <button
            type="button"
            className="btn btn-ghost"
            onClick={() => {
              setConfig(defaultRunConfig());
              setFiles(EMPTY_FILES);
              setSelectedProfile('');
              setError(null);
              setResetKey((k) => k + 1);
            }}
          >
            Reset form
          </button>
        </div>
      </form>
    </>
  );
}
