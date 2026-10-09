// Where a client checks a report: the public verifier page, or the offline verifier and the
// timestamp roots it trusts, which this deployment serves. In the demo they sit next to the app.

import { DEMO } from "./demo";

export const VERIFY_PAGE = "https://attackledger.com/verify";

const ROOTS_FILE = DEMO ? "digicert-trusted-root-g4.pem" : "tsa-roots.pem";
export const VERIFIER = {
  script: DEMO ? "../verify_report.py" : "/api/verifier/verify_report.py",
  roots: DEMO ? `../${ROOTS_FILE}` : "/api/verifier/tsa-roots",
  rootsFile: ROOTS_FILE,   // the name the download is saved under, as the command uses it
  command: (file: string) => `python3 verify_report.py ${file} --tsa-root ${ROOTS_FILE}`,
};
