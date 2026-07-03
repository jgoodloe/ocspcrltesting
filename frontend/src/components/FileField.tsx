import { useRef, useState } from 'react';
import { ApiError, inspectCertificate, type CertMetadata } from '../lib/api';
import { CertMetaCard } from './CertMetaCard';

export interface FileFieldProps {
  label: string;
  required?: boolean;
  hint?: string;
  /**
   * When true the file is a private key: never inspected, never previewed —
   * only the file name is shown.
   */
  sensitive?: boolean;
  file: File | null;
  onChange: (file: File | null) => void;
  accept?: string;
}

/**
 * Certificate/key file picker. For non-sensitive files it calls the inspect
 * endpoint on selection and renders a compact metadata card.
 */
export function FileField({
  label,
  required,
  hint,
  sensitive,
  file,
  onChange,
  accept = '.pem,.crt,.cer,.der,.key',
}: FileFieldProps) {
  const [meta, setMeta] = useState<CertMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleSelect = async (selected: File | null) => {
    onChange(selected);
    setMeta(null);
    setError(null);
    if (!selected || sensitive) return;
    setInspecting(true);
    try {
      const parsed = await inspectCertificate(selected);
      setMeta(parsed);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.detail);
      } else {
        setError('Could not inspect certificate.');
      }
    } finally {
      setInspecting(false);
    }
  };

  const clear = () => {
    if (inputRef.current) inputRef.current.value = '';
    void handleSelect(null);
  };

  return (
    <div className="field">
      <span className="field-label">
        {label}
        {required && <span className="req">*</span>}
      </span>
      <div className="form-row">
        <input
          ref={inputRef}
          className="file-input"
          type="file"
          accept={accept}
          aria-label={label}
          onChange={(e) => void handleSelect(e.target.files?.[0] ?? null)}
        />
        {file && (
          <button type="button" className="btn btn-ghost btn-sm" onClick={clear}>
            Clear
          </button>
        )}
      </div>
      {hint && <span className="field-hint">{hint}</span>}
      {sensitive && file && (
        <span className="field-hint mono">
          {file.name} — key material is uploaded but never inspected or displayed.
        </span>
      )}
      {inspecting && <span className="field-hint">Inspecting…</span>}
      {error && (
        <div className="form-error">
          <span className="err-status">Invalid file</span>
          {error}
        </div>
      )}
      {meta && !sensitive && <CertMetaCard meta={meta} />}
    </div>
  );
}
