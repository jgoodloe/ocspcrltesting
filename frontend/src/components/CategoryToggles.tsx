import type { CategoryFlags } from '../lib/api';

export const CATEGORY_DEFS: Array<{
  key: keyof CategoryFlags;
  name: string;
  desc: string;
}> = [
  { key: 'protocol', name: 'OCSP protocol', desc: 'RFC 6960 request/response conformance' },
  { key: 'status', name: 'Certificate status', desc: 'good / revoked / unknown responses' },
  { key: 'crl', name: 'CRL', desc: 'CRL download, signature, freshness' },
  { key: 'path_validation', name: 'Path validation', desc: 'RFC 5280 chain building and policies' },
  { key: 'ikev2', name: 'IKEv2', desc: 'IKEv2 OCSP payload compatibility' },
  { key: 'federal', name: 'Federal PKI / Federal Bridge', desc: 'FPKI profile and bridge CA checks' },
  { key: 'performance', name: 'Performance (OCSP)', desc: 'OCSP responder latency sampling and optional load test' },
  { key: 'security', name: 'Security & error handling (OCSP)', desc: 'OCSP malformed input, replay, error robustness' },
];

export function CategoryToggles({
  value,
  onChange,
}: {
  value: CategoryFlags;
  onChange: (next: CategoryFlags) => void;
}) {
  return (
    <div className="category-toggle-grid">
      {CATEGORY_DEFS.map((def) => {
        const on = value[def.key];
        return (
          <label key={def.key} className={`category-toggle${on ? ' on' : ''}`}>
            <input
              type="checkbox"
              checked={on}
              onChange={(e) => onChange({ ...value, [def.key]: e.target.checked })}
            />
            <span>
              <span className="ct-name">{def.name}</span>
              <br />
              <span className="ct-desc">{def.desc}</span>
            </span>
          </label>
        );
      })}
    </div>
  );
}
