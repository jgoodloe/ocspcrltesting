import type { ChangeEvent } from 'react';
import { Link } from 'react-router-dom';
import type { RunConfig, TestSelectionMode } from '../lib/api';
import { CategoryToggles } from './CategoryToggles';
import { TestSelectionEditor } from './TestSelectionEditor';

/**
 * All RunConfig option fields (everything except file uploads and the run
 * name). Shared between the New Run form and the Profile editor.
 */
export function ConfigFields({
  config,
  onChange,
}: {
  config: RunConfig;
  onChange: (next: RunConfig) => void;
}) {
  const set = <K extends keyof RunConfig>(key: K, value: RunConfig[K]) =>
    onChange({ ...config, [key]: value });

  const num =
    <K extends keyof RunConfig>(key: K) =>
    (e: ChangeEvent<HTMLInputElement>) => {
      const v = e.target.value === '' ? 0 : Number(e.target.value);
      set(key, (Number.isNaN(v) ? 0 : v) as RunConfig[K]);
    };

  const setCrlUrl = (index: number, value: string) => {
    const next = [...config.crl_urls];
    next[index] = value;
    set('crl_urls', next);
  };

  return (
    <>
      <div className="field">
        <span className="field-label">
          OCSP responder URL<span className="req">*</span>
        </span>
        <input
          className="input mono"
          type="url"
          required
          placeholder="http://ocsp.example.com"
          value={config.ocsp_url}
          onChange={(e) => set('ocsp_url', e.target.value)}
        />
      </div>

      <div className="field">
        <span className="field-label">CRL URLs (optional)</span>
        {config.crl_urls.map((url, i) => (
          <div className="form-row" key={i}>
            <input
              className="input mono"
              type="url"
              placeholder="http://crl.example.com/ca.crl"
              value={url}
              onChange={(e) => setCrlUrl(i, e.target.value)}
              aria-label={`CRL URL ${i + 1}`}
            />
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() =>
                set(
                  'crl_urls',
                  config.crl_urls.filter((_, j) => j !== i),
                )
              }
              aria-label={`Remove CRL URL ${i + 1}`}
            >
              Remove
            </button>
          </div>
        ))}
        <div>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => set('crl_urls', [...config.crl_urls, ''])}
          >
            + Add CRL URL
          </button>
        </div>
      </div>

      <h3 className="section-label">Request options</h3>
      <div className="form-grid">
        <div className="field">
          <span className="field-label">Request method</span>
          <select
            className="select"
            value={config.request_method}
            onChange={(e) => set('request_method', e.target.value as RunConfig['request_method'])}
          >
            <option value="auto">Auto</option>
            <option value="get">GET</option>
            <option value="post">POST</option>
          </select>
        </div>
        <div className="field">
          <span className="field-label">Nonce</span>
          <label className="checkbox-row" style={{ marginTop: 6 }}>
            <input
              type="checkbox"
              checked={config.nonce_enabled}
              onChange={(e) => set('nonce_enabled', e.target.checked)}
            />
            Enable nonce (RFC 9654)
          </label>
        </div>
        {config.nonce_enabled && (
          <div className="field">
            <span className="field-label">Nonce length (bytes)</span>
            <input
              className="input"
              type="number"
              min={1}
              max={128}
              value={config.nonce_length}
              onChange={num('nonce_length')}
            />
            <span className="field-hint">1–128, default 32</span>
          </div>
        )}
        <div className="field">
          <span className="field-label">Latency samples</span>
          <input
            className="input"
            type="number"
            min={1}
            max={100}
            value={config.latency_samples}
            onChange={num('latency_samples')}
          />
          <span className="field-hint">1–100</span>
        </div>
      </div>

      <div className="field">
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={config.enable_load_test}
            onChange={(e) => set('enable_load_test', e.target.checked)}
          />
          Enable load test
        </label>
      </div>
      {config.enable_load_test && (
        <div className="form-grid">
          <div className="field">
            <span className="field-label">Load concurrency</span>
            <input
              className="input"
              type="number"
              min={1}
              max={64}
              value={config.load_concurrency}
              onChange={num('load_concurrency')}
            />
            <span className="field-hint">1–64</span>
          </div>
          <div className="field">
            <span className="field-label">Load requests</span>
            <input
              className="input"
              type="number"
              min={1}
              max={2000}
              value={config.load_requests}
              onChange={num('load_requests')}
            />
            <span className="field-hint">1–2000</span>
          </div>
        </div>
      )}

      <h3 className="section-label">Timeouts and freshness</h3>
      <div className="form-grid">
        <div className="field">
          <span className="field-label">Per-request timeout (s)</span>
          <input
            className="input"
            type="number"
            min={1}
            max={120}
            value={config.timeout_seconds}
            onChange={num('timeout_seconds')}
          />
          <span className="field-hint">1–120</span>
        </div>
        <div className="field">
          <span className="field-label">Run timeout (s)</span>
          <input
            className="input"
            type="number"
            min={30}
            max={7200}
            value={config.run_timeout_seconds}
            onChange={num('run_timeout_seconds')}
          />
          <span className="field-hint">30–7200</span>
        </div>
        <div className="field">
          <span className="field-label">Max response age (hours)</span>
          <input
            className="input"
            type="number"
            min={0}
            value={config.max_age_hours}
            onChange={num('max_age_hours')}
          />
        </div>
      </div>

      <h3 className="section-label">Path validation</h3>
      <div className="form-grid">
        <div className="field">
          <span className="field-label">Trust anchor type</span>
          <select
            className="select"
            value={config.trust_anchor_type}
            onChange={(e) =>
              set('trust_anchor_type', e.target.value as RunConfig['trust_anchor_type'])
            }
          >
            <option value="root">Root</option>
            <option value="intermediate">Intermediate</option>
          </select>
        </div>
        <div className="field">
          <span className="field-label">Policy constraints</span>
          <label className="checkbox-row" style={{ marginTop: 6 }}>
            <input
              type="checkbox"
              checked={config.require_explicit_policy}
              onChange={(e) => set('require_explicit_policy', e.target.checked)}
            />
            Require explicit policy
          </label>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={config.inhibit_policy_mapping}
              onChange={(e) => set('inhibit_policy_mapping', e.target.checked)}
            />
            Inhibit policy mapping
          </label>
        </div>
      </div>

      <h3 className="section-label">Test categories</h3>
      <CategoryToggles
        value={config.categories}
        onChange={(categories) => set('categories', categories)}
      />

      <h3 className="section-label" style={{ marginTop: 16 }}>
        Test selection
      </h3>
      <div className="field">
        <span className="field-label">Which tests run inside the enabled categories</span>
        <select
          className="select"
          style={{ maxWidth: 420 }}
          value={config.test_selection.mode}
          onChange={(e) =>
            set('test_selection', {
              ...config.test_selection,
              mode: e.target.value as TestSelectionMode,
            })
          }
          aria-label="Test selection mode"
        >
          <option value="all">All tests (default)</option>
          <option value="global">Use the global test selection</option>
          <option value="custom">Custom selection for this configuration</option>
        </select>
        {config.test_selection.mode === 'global' && (
          <span className="field-hint">
            The server-wide selection from <Link to="/settings">Settings</Link> is applied when the
            run starts.
          </span>
        )}
      </div>
      {config.test_selection.mode === 'custom' && (
        <TestSelectionEditor
          value={config.test_selection.tests}
          enabledCategories={config.categories}
          onChange={(tests) =>
            set('test_selection', { ...config.test_selection, tests })
          }
        />
      )}
    </>
  );
}
