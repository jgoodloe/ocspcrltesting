import { useEffect, useState } from 'react';
import {
  getTestCatalog,
  type CatalogCategory,
  type CategoryFlags,
  type TestCatalog,
} from '../lib/api';

let catalogCache: TestCatalog | null = null;

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

function CategorySection({
  category,
  selected,
  onChange,
  disabled,
}: {
  category: CatalogCategory;
  /** undefined = category unrestricted (all tests run) */
  selected: string[] | undefined;
  onChange: (next: string[] | undefined) => void;
  disabled?: boolean;
}) {
  const restricted = selected !== undefined;
  const selectedSet = new Set(selected ?? []);
  const total = category.tests.length;
  const count = restricted ? selectedSet.size : total;

  const toggleTest = (name: string) => {
    const next = new Set(selectedSet);
    if (next.has(name)) next.delete(name);
    else next.add(name);
    onChange(Array.from(next));
  };

  const summaryId = `tsel-${category.key}`;

  return (
    <fieldset className={`tsel-category${disabled ? ' disabled' : ''}`} disabled={disabled}>
      <legend className="tsel-legend">
        <span className="tsel-cat-name">{category.label}</span>
        <span className="tsel-count" aria-live="polite">
          {count} of {total} test{total === 1 ? '' : 's'}
          {disabled ? ' (category disabled)' : ''}
        </span>
      </legend>
      <div className="tsel-controls">
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={!restricted}
            aria-describedby={summaryId}
            onChange={(e) => onChange(e.target.checked ? undefined : category.tests.map((t) => t.name))}
          />
          Run all tests in this category
        </label>
        {restricted && (
          <span className="tsel-quick">
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => onChange(category.tests.map((t) => t.name))}
            >
              Select all
            </button>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => onChange([])}>
              Select none
            </button>
          </span>
        )}
      </div>
      <p className="visually-hidden" id={summaryId}>
        Unchecking lets you pick individual tests for {category.label}.
      </p>
      {restricted && (
        <ul className="tsel-test-list">
          {category.tests.map((t) => (
            <li key={t.name}>
              <label className="checkbox-row tsel-test">
                <input
                  type="checkbox"
                  checked={selectedSet.has(t.name)}
                  onChange={() => toggleTest(t.name)}
                />
                <span>
                  <span className="tsel-test-name">{t.name}</span>
                  {t.description && <span className="tsel-test-desc">{t.description}</span>}
                </span>
              </label>
            </li>
          ))}
        </ul>
      )}
    </fieldset>
  );
}

/**
 * Per-category, per-test checkbox editor for a test selection map.
 * A category missing from `value` runs all of its tests.
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

  const setCategory = (key: string, selected: string[] | undefined) => {
    const next = { ...value };
    if (selected === undefined) delete next[key];
    else next[key] = selected;
    onChange(next);
  };

  return (
    <div className="tsel-editor">
      {catalog.categories.map((cat) => (
        <CategorySection
          key={cat.key}
          category={cat}
          selected={value[cat.key]}
          onChange={(sel) => setCategory(cat.key, sel)}
          disabled={
            enabledCategories
              ? !enabledCategories[cat.key as keyof CategoryFlags]
              : false
          }
        />
      ))}
    </div>
  );
}
