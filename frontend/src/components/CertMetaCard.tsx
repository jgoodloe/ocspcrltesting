import type { CertMetadata } from '../lib/api';
import { formatDateTime } from '../lib/format';

/** Compact metadata card shown under a certificate file picker. */
export function CertMetaCard({ meta }: { meta: CertMetadata }) {
  return (
    <div className="cert-card">
      <dl>
        <dt>Subject</dt>
        <dd>{meta.subject}</dd>
        <dt>Issuer</dt>
        <dd>{meta.issuer}</dd>
        <dt>Serial</dt>
        <dd>{meta.serial_number}</dd>
        <dt>Validity</dt>
        <dd className={meta.expired ? 'expired' : undefined}>
          {formatDateTime(meta.not_before)} → {formatDateTime(meta.not_after)}
          {meta.expired ? ' (EXPIRED)' : ''}
        </dd>
        <dt>Key</dt>
        <dd>{meta.key_algorithm}</dd>
        <dt>Signature</dt>
        <dd>
          {meta.signature_algorithm} ({meta.signature_algorithm_oid})
        </dd>
        {meta.ski && (
          <>
            <dt>SKI</dt>
            <dd>{meta.ski}</dd>
          </>
        )}
        {meta.aki && (
          <>
            <dt>AKI</dt>
            <dd>{meta.aki}</dd>
          </>
        )}
        {meta.aia_ocsp_urls.length > 0 && (
          <>
            <dt>AIA OCSP</dt>
            <dd>{meta.aia_ocsp_urls.join(', ')}</dd>
          </>
        )}
        {meta.crl_distribution_points.length > 0 && (
          <>
            <dt>CRL DPs</dt>
            <dd>{meta.crl_distribution_points.join(', ')}</dd>
          </>
        )}
      </dl>
      <div className="cert-flags">
        {meta.is_ca && <span className="count-chip skip">CA</span>}
        {meta.self_signed && <span className="count-chip skip">self-signed</span>}
        {meta.expired && <span className="count-chip fail">expired</span>}
      </div>
    </div>
  );
}
