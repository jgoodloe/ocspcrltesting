import { useEffect, useState } from 'react';
import { TestSelectionEditor } from '../components/TestSelectionEditor';
import {
  ApiError,
  getGlobalTestSelection,
  putGlobalTestSelection,
} from '../lib/api';
import { formatDateTime } from '../lib/format';

/**
 * Server-wide settings. Currently hosts the global test selection: the
 * default set of individual tests applied to any run whose configuration
 * chooses "Use the global test selection".
 */
export function Settings() {
  const [tests, setTests] = useState<Record<string, string[]> | null>(null);
  const [restrict, setRestrict] = useState(false);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getGlobalTestSelection()
      .then((res) => {
        if (cancelled) return;
        setTests(res.tests);
        setRestrict(res.tests !== null);
        setUpdatedAt(res.updated_at);
        setLoaded(true);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof ApiError ? err.detail : 'Could not reach the API.');
        setLoaded(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      const res = await putGlobalTestSelection(restrict ? (tests ?? {}) : null);
      setTests(res.tests);
      setUpdatedAt(res.updated_at);
      setSaved(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : 'Save failed.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <div className="page-header">
        <div>
          <h1 className="page-title">Settings</h1>
          <p className="page-subtitle">
            Server-wide defaults shared by every run and profile.
          </p>
        </div>
      </div>

      {error && (
        <div className="form-error" role="alert">
          <span className="err-status">Error</span>
          {error}
        </div>
      )}
      {saved && (
        <div className="panel notice-ok" role="status" style={{ marginBottom: 14 }}>
          Global test selection saved.
        </div>
      )}

      <div className="panel">
        <h2 className="section-label">Global test selection</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Runs and profiles that choose <strong>Use the global test selection</strong> apply
          this set of tests. Runs configured with "All tests" or a custom selection are not
          affected.
          {updatedAt ? ` Last updated ${formatDateTime(updatedAt)}.` : ''}
        </p>
        {!loaded ? (
          <div className="loading">Loading…</div>
        ) : (
          <>
            <div className="field">
              <label className="checkbox-row">
                <input
                  type="checkbox"
                  checked={restrict}
                  onChange={(e) => {
                    setRestrict(e.target.checked);
                    if (e.target.checked && tests === null) setTests({});
                  }}
                />
                Restrict which tests run globally
              </label>
              <span className="field-hint">
                Unchecked: the global selection runs every test in each enabled category.
              </span>
            </div>
            {restrict && (
              <TestSelectionEditor
                value={tests ?? {}}
                onChange={(next) => setTests(next)}
              />
            )}
            <div className="toolbar" style={{ marginTop: 16 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => void handleSave()}
                disabled={saving}
              >
                {saving ? 'Saving…' : 'Save global selection'}
              </button>
            </div>
          </>
        )}
      </div>
    </>
  );
}
