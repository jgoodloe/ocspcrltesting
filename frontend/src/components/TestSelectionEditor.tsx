import { useEffect, useMemo, useRef, useState } from 'react';
import {
  getTestCatalog,
  type CatalogCategory,
  type CategoryFlags,
  type TestCatalog,
} from '../lib/api';

let catalogCache: TestCatalog | null = null;

const SCOPE_LABELS: Record<string, string> = {
  ocsp: 'OCSP',
  crl: 'CRL',
  'crl+ocsp': 'CRL+OCSP',
  path: 'Path',
  ikev2: 'IKEv2',
};

/** Small badge marking what a test exercises (OCSP vs CRL vs path…). */
export function ScopeBadge({ scope }: { scope: string | undefined }) {
  if (!scope) return null;
  return (
    <span className={`scope-badge scope-${scope.replace('+', '-')}`}>
      {SCOPE_LABELS[scope] ?? scope.toUpperCase()}
    </span>
  );
}

/** Fetch the test catalog once per app session. */
export function useTestCatalog(): { catalog: TestCatalog | null; error: string | null } {
  const [catalog, setCatalog] = useState<TestCatalog | null>(catalogCache);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (catalogCache) return;
    let cancelled = false;
    getTestCatalog()
      .then((c) => {
        catalogCache = c;
        if (!cancelled) setCatalog(c);
      })
      .catch(() => {
        if (!cancelled) setError('Could not load the test catalog.');
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return { catalog, error };
}

/** Checkbox that can render the native indeterminate ("some selected") state. */
function TriStateCheckbox({
  checked,
  indeterminate,
  onChange,
  ariaLabel,
  disabled,
}: {
  checked: boolean;
  indeterminate: boolean;
  onChange: () => void;
  ariaLabel: string;
  disabled?: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = indeterminate;
  }, [indeterminate]);
  return (
    <input
      ref={ref}
      type="checkbox"
      checked={checked}
      disabled={disabled}
      aria-label={ariaLabel}
      onClick={(e) => e.stopPropagation()}
      onChange={onChange}
    />
  );
}

function CategorySection({
  category,
  selected,
  onChange,
  disabled,
  query,
}: {
  category: CatalogCategory;
  /** undefined = category unrestricted (all tests run) */
  selected: string[] | undefined;
  onChange: (next: string[] | undefined) => void;
  disabled: boolean;
  query: string;
}) {
  const [openManual, setOpenManual] = useState(false);

  const allNames = useMemo(() => category.tests.map((t) => t.name), [category]);
  const selectedSet = useMemo(
    () => (selected === undefined ? new Set(allNames) : new Set(selected)),
    [selected, allNames],
  );
  const total = allNames.length;
  const count = allNames.filter((n) => selectedSet.has(n)).length;
  const allOn = count === total;
  const noneOn = count === 0;

  const q = query.trim().toLowerCase();
  const visibleTests = q
    ? category.tests.filter(
        (t) =>
          t.name.toLowerCase().includes(q) || t.description.toLowerCase().includes(q),
      )
    : category.tests;
  // While searching, auto-expand categories with matches and hide the rest.
  const searching = q.length > 0;
  if (searching && visibleTests.length === 0) return null;
  const open = searching || openManual;

  const toggleAll = () => {
    // Checked (all or some) -> none; unchecked -> all.
    if (noneOn) onChange(undefined);
    else onChange([]);
  };

  const toggleTest = (name: string) => {
    const next = new Set(selectedSet);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    // Back at "everything checked" = unrestricted again.
    onChange(next.size === total ? undefined : allNames.filter((n) => next.has(n)));
  };

  const listId = `tsel-list-${category.key}`;

  return (
    <section className={`tsel-category${disabled ? ' disabled' : ''}`}>
      <div className="tsel-header">
        <TriStateCheckbox
          checked={!noneOn}
          indeterminate={!allOn && !noneOn}
          onChange={toggleAll}
          ariaLabel={`Toggle all ${category.label}`}
          disabled={disabled}
        />
        <button
          type="button"
          className="tsel-header-btn"
          aria-expanded={open}
          aria-controls={listId}
          onClick={() => setOpenManual((v) => !v)}
        >
          <span className={`tsel-chevron${open ? ' open' : ''}`} aria-hidden="true">
            ▸
          </span>
          <span className="tsel-cat-name">{category.label}</span>
          <span
            className={`tsel-count${allOn ? '' : noneOn ? ' none' : ' some'}`}
          >
            {count}/{total}
          </span>
          {disabled && <span className="tsel-disabled-note">category disabled for this run</span>}
        </button>
      </div>
      {open && (
        <ul className="tsel-test-list" id={listId}>
          {visibleTests.map((t) => (
            <li key={t.name}>
              <label className="checkbox-row tsel-test">
                <input
                  type="checkbox"
                  checked={selectedSet.has(t.name)}
                  disabled={disabled}
                  onChange={() => toggleTest(t.name)}
                />
                <span>
                  <span className="tsel-test-name">
                    {t.name} <ScopeBadge scope={t.scope} />
                  </span>
                  {t.description && <span className="tsel-test-desc">{t.description}</span>}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * Per-category, per-test editor for a test selection map.
 * A category missing from `value` runs all of its tests.
 *
 * Categories collapse to a single row with a tri-state checkbox
 * (checked = all, dash = some, unchecked = none); expand a row or type in
 * the search box to pick individual tests.
 */
export function TestSelectionEditor({
  value,
  onChange,
  enabledCategories,
}: {
  value: Record<string, string[]>;
  onChange: (next: Record<string, string[]>) => void;
  /** When provided, categories toggled off in the run config are dimmed. */
  enabledCategories?: CategoryFlags;
}) {
  const { catalog, error } = useTestCatalog();
  const [query, setQuery] = useState('');

  if (error) {
    return (
      <div className="form-error" role="alert">
        <span className="err-status">Error</span>
        {error}
      </div>
    );
  }
  if (!catalog) {
    return <div className="loading">Loading test catalog…</div>;
  }

  const isEnabled = (key: string) =>
    !enabledCategories || Boolean(enabledCategories[key as keyof CategoryFlags]);

  const setCategory = (key: string, selected: string[] | undefined) => {
    const next = { ...value };
    if (selected === undefined) delete next[key];
    else next[key] = selected;
    onChange(next);
  };

  // Counts only cover categories enabled for the run.
  const counted = catalog.categories.filter((c) => isEnabled(c.key));
  const totalTests = counted.reduce((n, c) => n + c.tests.length, 0);
  const selectedTests = counted.reduce((n, c) => {
    const sel = value[c.key];
    if (sel === undefined) return n + c.tests.length;
    const names = new Set(c.tests.map((t) => t.name));
    return n + sel.filter((s) => names.has(s)).length;
  }, 0);

  return (
    <div className="tsel-editor">
      <div className="tsel-toolbar">
        <input
          className="input"
          type="search"
          placeholder="Search tests…"
          style={{ maxWidth: 260 }}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search tests"
        />
        <button type="button" className="btn btn-sm" onClick={() => onChange({})}>
          Select all
        </button>
        <button
          type="button"
          className="btn btn-sm"
          onClick={() =>
            onChange(
              Object.fromEntries(catalog.categories.map((c) => [c.key, []])),
            )
          }
        >
          Clear all
        </button>
        <span className="spacer" />
        <span className="tsel-summary" role="status">
          {selectedTests} of {totalTests} tests will run
        </span>
      </div>
      {catalog.categories.map((cat) => (
        <CategorySection
          key={cat.key}
          category={cat}
          selected={value[cat.key]}
          onChange={(sel) => setCategory(cat.key, sel)}
          disabled={!isEnabled(cat.key)}
          query={query}
        />
      ))}
      {query.trim() &&
        catalog.categories.every((c) => {
          const q = query.trim().toLowerCase();
          return !c.tests.some(
            (t) =>
              t.name.toLowerCase().includes(q) ||
              t.description.toLowerCase().includes(q),
          );
        }) && <div className="table-empty">No tests match “{query.trim()}”.</div>}
    </div>
  );
}
