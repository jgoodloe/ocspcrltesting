import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { ConfigFields } from '../components/ConfigFields';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { ShareDialog } from '../components/ShareDialog';
import {
  ApiError,
  createProfile,
  defaultRunConfig,
  deleteProfile,
  getActiveWorkspaceId,
  listProfiles,
  shareProfile,
  updateProfile,
  type Profile,
  type RunConfig,
} from '../lib/api';
import { formatDateTime } from '../lib/format';

interface EditorState {
  /** null = creating a new profile */
  profile: Profile | null;
  name: string;
  description: string;
  config: RunConfig;
}

function emptyEditor(): EditorState {
  const config = defaultRunConfig();
  delete config.profile_id;
  return { profile: null, name: '', description: '', config };
}

function editorFor(profile: Profile): EditorState {
  const defaults = defaultRunConfig();
  return {
    profile,
    name: profile.name,
    description: profile.description ?? '',
    config: {
      ...defaults,
      ...profile.config,
      categories: { ...defaults.categories, ...profile.config.categories },
      profile_id: undefined,
    },
  };
}

export function Profiles() {
  const navigate = useNavigate();
  const [profiles, setProfiles] = useState<Profile[] | null>(null);
  const [editor, setEditor] = useState<EditorState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<Profile | null>(null);
  const [pendingShare, setPendingShare] = useState<Profile | null>(null);
  const [shareBusy, setShareBusy] = useState(false);

  const load = async () => {
    try {
      const res = await listProfiles();
      setProfiles(res.items);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Could not reach the API.');
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const handleSave = async (e: FormEvent) => {
    e.preventDefault();
    if (!editor) return;
    setFormError(null);
    if (!editor.name.trim()) {
      setFormError('Profile name is required.');
      return;
    }
    if (!editor.config.ocsp_url.trim()) {
      setFormError('OCSP responder URL is required.');
      return;
    }
    setSaving(true);
    try {
      const { profile_id: _omit, ...config } = editor.config;
      const input = {
        name: editor.name.trim(),
        description: editor.description.trim() || null,
        config: {
          ...config,
          ocsp_url: editor.config.ocsp_url.trim(),
          crl_urls: editor.config.crl_urls.map((u) => u.trim()).filter(Boolean),
        } as RunConfig,
      };
      if (editor.profile) {
        await updateProfile(editor.profile.id, input);
      } else {
        await createProfile(input);
      }
      setEditor(null);
      void load();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.detail : 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteProfile(pendingDelete.id);
      setPendingDelete(null);
      void load();
    } catch (err) {
      setPendingDelete(null);
      setError(err instanceof ApiError ? err.detail : 'Delete failed.');
    }
  };

  const handleShare = async (targetWorkspaceId: number) => {
    if (!pendingShare) return;
    setShareBusy(true);
    setError(null);
    setNotice(null);
    try {
      await shareProfile(pendingShare.id, targetWorkspaceId);
      setNotice(`Shared “${pendingShare.name}” to the selected workspace.`);
      setPendingShare(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Share failed.');
    } finally {
      setShareBusy(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Profiles</h1>
          <p className="page-subtitle">
            Saved test configurations. Certificates are uploaded per run and are
            never stored in a profile.
          </p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => {
            setEditor(emptyEditor());
            setFormError(null);
          }}
        >
          New profile
        </button>
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

      {editor && (
        <form className="panel" onSubmit={(e) => void handleSave(e)} noValidate>
          <div className="panel-header">
            <h2 className="section-label" style={{ margin: 0 }}>
              {editor.profile ? `Edit profile: ${editor.profile.name}` : 'New profile'}
            </h2>
          </div>
          {formError && (
            <div className="form-error" role="alert">
              <span className="err-status">Error</span>
              {formError}
            </div>
          )}
          <div className="form-grid">
            <div className="field">
              <span className="field-label">
                Profile name<span className="req">*</span>
              </span>
              <input
                className="input"
                value={editor.name}
                onChange={(e) => setEditor({ ...editor, name: e.target.value })}
              />
            </div>
            <div className="field">
              <span className="field-label">Description</span>
              <input
                className="input"
                value={editor.description}
                onChange={(e) => setEditor({ ...editor, description: e.target.value })}
              />
            </div>
          </div>
          <ConfigFields
            config={editor.config}
            onChange={(config) => setEditor({ ...editor, config })}
          />
          <div className="toolbar" style={{ marginTop: 16 }}>
            <button type="submit" className="btn btn-primary" disabled={saving}>
              {saving ? 'Saving…' : editor.profile ? 'Save changes' : 'Create profile'}
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => setEditor(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div className="panel">
        {profiles === null ? (
          <div className="loading">Loading…</div>
        ) : profiles.length === 0 ? (
          <div className="table-empty">No profiles saved yet.</div>
        ) : (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Description</th>
                  <th scope="col">OCSP URL</th>
                  <th scope="col">Updated</th>
                  <th scope="col" aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {profiles.map((p) => (
                  <tr key={p.id}>
                    <td style={{ fontWeight: 600 }}>{p.name}</td>
                    <td className="muted">{p.description || '—'}</td>
                    <td className="mono truncate">{p.config.ocsp_url}</td>
                    <td className="nowrap muted">{formatDateTime(p.updated_at)}</td>
                    <td className="nowrap" style={{ textAlign: 'right' }}>
                      <span className="toolbar" style={{ justifyContent: 'flex-end' }}>
                        <button
                          type="button"
                          className="btn btn-sm btn-primary"
                          onClick={() => navigate(`/runs/new?profile=${p.id}`)}
                        >
                          Start run
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => {
                            setEditor(editorFor(p));
                            setFormError(null);
                            window.scrollTo({ top: 0 });
                          }}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="btn btn-sm"
                          onClick={() => {
                            setPendingShare(p);
                            setError(null);
                            setNotice(null);
                          }}
                        >
                          Share
                        </button>
                        <button
                          type="button"
                          className="btn btn-ghost btn-sm"
                          onClick={() => setPendingDelete(p)}
                        >
                          Delete
                        </button>
                      </span>
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
          title="Delete this profile?"
          confirmLabel="Delete profile"
          danger
          onConfirm={() => void handleDelete()}
          onCancel={() => setPendingDelete(null)}
        >
          {`Deletes profile “${pendingDelete.name}”. Existing runs are not affected.`}
        </ConfirmDialog>
      )}

      {pendingShare && (
        <ShareDialog
          title="Share profile"
          itemName={pendingShare.name}
          sourceWorkspaceId={getActiveWorkspaceId()}
          busy={shareBusy}
          onShare={(id) => void handleShare(id)}
          onClose={() => setPendingShare(null)}
        />
      )}
    </>
  );
}
