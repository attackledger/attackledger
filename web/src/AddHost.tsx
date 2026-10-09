import { FormEvent, useState } from "react";
import { api } from "./api";

/** Add one host to an engagement: the Ledger's form, also offered on Recon when there are no hosts yet. */
export function AddHost({ engId, onAdded, id = "new-host", className = "inline-form add-host" }: {
  engId: number; onAdded: () => void; id?: string; className?: string;
}) {
  const [host, setHost] = useState("");
  const [inScope, setInScope] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [added, setAdded] = useState<string | null>(null);

  async function add(ev: FormEvent) {
    ev.preventDefault();
    const h = host.trim();
    if (!h) return;
    try {
      await api.addAsset(engId, h, inScope);
      setHost("");
      setError(null);
      setAdded(`Added ${h}${inScope ? "" : " as out of scope"}.`);
      onAdded();
    } catch (e) {
      setAdded(null);
      setError((e as Error).message);
    }
  }

  return (
    <form className={className} onSubmit={add}>
      <label htmlFor={id}>Add a host</label>
      <div className="field-row">
        <input id={id} value={host} onChange={(e) => setHost(e.target.value)} placeholder="app.example.com" />
        <label className="check">
          <input type="checkbox" checked={inScope} onChange={(e) => setInScope(e.target.checked)} />
          In scope
        </label>
        <button type="submit" className="btn" disabled={!host.trim()}>Add host</button>
      </div>
      {error && <p className="field-error" role="alert">{error}</p>}
      {added && !error && <p className="saved" role="status">{added}</p>}
    </form>
  );
}
