// Where a client checks a report without this app. The independent copies on attackledger.com come
// first, because they do not depend on this server; this server's own copy follows, with its SHA-256
// so the reader can compare the two. The demo has no server: it ships the script and root next to it.

import { useEffect, useState } from "react";
import { api, type VerifierIndex } from "./api";
import { DEMO } from "./demo";

export const VERIFY_PAGE = "https://attackledger.com/verify";
const PUBLIC_SCRIPT = DEMO ? "../verify_report.py" : "https://attackledger.com/verify_report.py";
const PUBLIC_ROOT = DEMO ? "../digicert-trusted-root-g4.pem" : "https://attackledger.com/digicert-trusted-root-g4.pem";
const ROOT_FILE = "digicert-trusted-root-g4.pem";

/** The offline check, for a report saved as `file`. `saved`: the download is already named `file`. */
export function OfflineVerifier({ file, saved = false }: { file: string; saved?: boolean }) {
  const [index, setIndex] = useState<VerifierIndex | null>(null);
  useEffect(() => { if (!DEMO) api.verifier().then(setIndex).catch(() => setIndex(null)); }, []);

  return (
    <>
      <p className="muted">
        The same check offline needs only Python and no AttackLedger install. Get{" "}
        <a href={PUBLIC_SCRIPT} download={DEMO ? "verify_report.py" : undefined}>verify_report.py</a> and the timestamp
        root it trusts, <a href={PUBLIC_ROOT} download={DEMO ? ROOT_FILE : undefined}>{ROOT_FILE}</a>
        {DEMO ? "" : " from attackledger.com"},{" "}
        {saved ? <>put the downloaded report, <code>{file}</code>, next to them</> : <>save the report as <code>{file}</code> next to them</>},
        {" "}and run:
      </p>
      <pre className="cmd" tabIndex={0} aria-label="Command">{`python3 -I verify_report.py ${file} --tsa-root ${ROOT_FILE}`}</pre>
      {index && (
        <p className="muted">
          This server has the same verifier:{" "}
          <a href={`/api${index.bundle.path}`} download={index.bundle.name}>download {index.bundle.name}</a>{" "}
          (the script with <code>tsa-roots/</code> beside it; in its folder, run the command without{" "}
          <code>--tsa-root</code>). A copy from the server whose report you are checking proves less than an independent
          one: before relying on it, check that its <code>verify_report.py</code> has the same SHA-256 as the copy from
          attackledger.com (<code>shasum -a 256 verify_report.py</code> on each). This server's copy has SHA-256{" "}
          <code className="hash-wrap">{index.script.sha256}</code>.
        </p>
      )}
    </>
  );
}
