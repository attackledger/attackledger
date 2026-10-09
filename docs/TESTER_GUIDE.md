# Tester guide

This guide is for a pentester working on an engagement in AttackLedger. You keep testing
with your own tools (Burp, Caido, a browser, scanners). AttackLedger holds the engagement's
rules, records what you tested against each checklist item, and gets each lane signed by a
reviewer, so the client receives a report they can check for themselves.

The words used below:

| Word | Meaning |
|---|---|
| Engagement | One test: a client or program, its scope and rules, its team. |
| Host | A row in the ledger, such as `app.example.com`. |
| Lane | One area of the methodology on one host, such as *Authentication* on `app.example.com`. A cell in the ledger. |
| Item | One line of a lane's checklist, such as *WSTG-ATHN-03 Test for weak lockout mechanisms*. |
| Evidence | What proves an item was tested: a note, a file, a recon run, an agent's request, or an imported request and response. |
| Receipt | A reviewer's signature over a lane: every item, its evidence or its reason. |

Your administrator installs AttackLedger (`docs/INSTALL.md`) and an owner of the engagement
gives you a role on it. To practise first, ask them for the lab engagement
(`docs/INSTALL.md`, section 19).

## 1. Sign in and choose your own password

1. Open the address your administrator gave you, such as `https://attackledger.example.com`.
2. Sign in with your email and the first password you were given.
3. Choose your own password straight away: **Your account** (bottom left), **Change your
   password**. Enter the current password, the new one twice (at least 12 characters), and
   **Change password**. This signs you out everywhere else.

Until you do, the app marks your account as "still signs in with a password someone else
set", and so does the log of any signing key you make. Nobody can set your password
through the app; a forgotten password is reset by the administrator on the server.

## 2. Open the engagement and read its rules

1. Choose the engagement in the **Engagements** list on the left. It opens on the
   **Ledger** tab.
2. Open the **Recon** tab. The bar at the top shows the rules the owner set:
   - **Scope**: the hosts and wildcards in scope, and how many exclusions. Exclusions
     always win.
   - **Rate limit**: the ceiling, in requests per second, for everything AttackLedger sends.
   - **Identification**: the research header (or user agent) sent on every request.
   - **Allowed extras**: optional modules the program allows.
   - **Evidence**: whether credentials are redacted before storage (always on for client
     work).
   - **Authorization**: who recorded the authorization, and when. Until it is recorded,
     nothing runs.

Only owners change the rules. Read the statement of work and rules of engagement (or, for
a bug bounty, the program's policy) too; AttackLedger enforces its own copy of the rules on
its own traffic, not on yours.

What AttackLedger itself sends (recon and the Claude agent) goes through its gateway, which
allows in-scope hosts only, read-only methods only (GET, HEAD, OPTIONS), and the rate limit.
Your own tools are your responsibility.

## 3. Lanes and checklist items

The **Ledger** tab is a table: one row per host, one column per lane. Each cell says where
that lane is:

| Mark | Meaning |
|---|---|
| **Not opened** | Not tested yet. Click it (**Open lane**) to start. |
| **In progress** | Open; shows how many items are still open, or "ready to sign". |
| **Receipted** | Signed by a reviewer. |
| **Void** | Changed after its receipt; it must be signed again. |
| **Needs …** | Only in packs that gate opening (the bug bounty pack): the lane opens after another lane on the same host is receipted. In the WSTG pack every lane opens at once, and the lane panel lists what must be receipted before it can be signed. |

A lane can be opened and worked before the lane it depends on is signed; only **closing**
it needs that lane receipted first.

Click a cell to open its lane panel. It shows the counts (done, evidence attached but not
marked done, not applicable, open), the checklist and the evidence. Each item is in one of
three states:

- **Open**: not resolved yet.
- **Done**: tested, with at least one evidence entry.
- **Not applicable**: with a written reason, shown to the reviewer and in the report.

A lane closes only when every item is done with evidence or not applicable with a reason.

To add a host that is in scope but not in the ledger yet, use **Add a host** under the
table.

## 4. Record evidence

Evidence can never be removed from the ledger, so check what you attach. Credentials,
tokens and keys are redacted before anything is stored (the entry says what was redacted);
other personal data and binary files are not.

**When the engagement's content is deleted** (an owner does it at the end of the
retention period), the raw bytes, notes, files, evidence summaries, recon results and
imported entries become unreadable or are removed. What stays, readable, for good:
- every evidence entry's **URL, with its host, path and query string** (after redaction),
  or an attached file's name, with its kind and hash;
- the items' not-applicable reasons;
- the receipts, their signatures and timestamps;
- the change history, the key log and the gateway's log of every request AttackLedger
  sent.

The URLs you test, the names of files you attach and the reasons you write outlive the
content, so keep confidential details out of file names and reasons.

### Manual: notes and files

In the lane panel, on the item:

1. **Add evidence**.
2. Choose the source:
   - **Note**: what you tested and what you saw, for example "GET /admin/ answers 401 with
     and without the session cookie."
   - **File**: a screenshot, a request and response export or tool output, up to 5 MB, with
     a sentence on what it shows.
3. **Attach evidence**. AttackLedger hashes it, keeps the bytes encrypted and links the
   entry into the evidence chain.

### Recon

On the **Recon** tab, **Run all steps**, or **Run step** for one step, or **Run** for one
tool. Each step checks the rules before it sends anything, and the results appear below
(golden targets, hosts, URLs, leads, runs). To use a finished run as evidence: on the item,
**Add evidence**, **Recon run**, choose the run, add a sentence, **Attach evidence**. The
run's output hash goes into the chain.

### The Claude agent

If your administrator turned agents on, a lane can be worked by a Claude agent instead of
by you:

1. In the lane panel, under **Who works this lane**, choose **Claude agent**.
2. Set the limits: **Turns**, **Requests**, **Cost limit, $**. The run stops at the first
   one it reaches.
3. **Start agent run**. The agent sends read-only requests to that host only, with the
   engagement's identification and rate limit, attaches evidence and marks items.
4. Read its evidence and what it left open (**Show log** shows each step). The agent cannot
   close a lane: a reviewer signs it, as for a manual lane.

### Test accounts for the agent

Authorization tests need signed-in sessions, often two (can A read B's order?). You create the
accounts on the target and sign in to them yourself; AttackLedger never creates accounts or
types passwords.

1. Open the **Test accounts** tab. Give the account a **Label** (A, B, ...), its **Role in the
   application**, and tick the in-scope **Hosts it is for**.
2. Choose what you are pasting: a **Cookie header** value, a **Bearer token**, or **Headers**
   (one `Name: value` per line), paste it and **Add test account**. It is stored encrypted and
   never shown again: the tab shows a fingerprint, when it was added, replaced and last used.
3. The agent sees only the labels and roles. When it sends a request "as A", the gateway adds A's
   session for those hosts only, and removes it from the response. The evidence says "as test
   account A".
4. When a session expires, sign in again and **Replace** it. **Delete** it when you are done.
   Every change is in the History tab, without the value. Deleting the engagement's data deletes
   the accounts too. Accounts need evidence redaction on.

### Writes the agent proposes

By default agents send read-only requests only. An owner can tick **Allow agents to propose
writes** on the **Approvals** tab. Then the agent may propose a POST, PUT, PATCH or DELETE; nothing
is sent until a tester approves it. The tab's badge counts what is waiting.

1. Read the whole request: method, URL, headers, body, the test account, the item and the agent's
   reason.
2. **Approve and send once**, with a note if you like, or write a note and **Reject**. The agent
   reads your note.
3. A DELETE needs a second step: type the URL's path exactly, then **Confirm DELETE**.
4. The approval is for that exact request and expires after 15 minutes. The agent's run sends it
   once, the next time it checks its writes; the exchange becomes evidence that says who approved
   it. If the run ends first, the write expires unsent.

With separation of duties on, whoever started the agent run cannot approve its writes. Viewers
and reviewers do not see the queue. The design is in `docs/APPROVALS.md`.

## 5. Import from Burp, Caido or a browser

Export the traffic from your tool, upload the file, then map each entry to checklist items.
Nothing reaches the ledger until a person maps it. Files are up to 50 MB and 5,000 entries
each; export fewer items if a file is bigger.

### Export the file

**Burp Suite** (Professional or Community), XML:

1. **Proxy**, **HTTP history**. Filter it to the host you are working on.
2. Select the requests (click one, then Ctrl+A, or Cmd+A on macOS, for all of them).
3. Right-click, **Save items**.
4. Keep **Base64-encode requests and responses** ticked (it keeps the bytes exact), choose
   a file name ending in `.xml`, and save.

**Caido**, JSON:

1. **HTTP History**. Filter it with an HTTPQL query to the host you are working on.
2. The **Export** menu, **Export all** (or **Export current rows** for the filtered rows only;
   it needs a paid Caido plan), **As JSON**.
3. Open the **Exports** page and download the file when it is ready.

**Caido, pulled from its API instead** (`tools/caido_pull.py`). Run this on your own
machine, next to Caido. It needs Python 3.9 or later and nothing else; copy the file from
the repository if you do not have a checkout.

1. Get a Caido access token. In Caido (signed in), open the developer tools
   (Ctrl+Shift+I), and in the **Console** run
   `JSON.parse(localStorage.CAIDO_AUTHENTICATION).accessToken`. Copy the value. It
   expires after 7 days. A personal access token from the Caido dashboard (it starts with
   `caido_`) does not work here.
2. Put it in an environment variable without typing it on the command line, so your shell
   history does not keep it: `read -rs CAIDO_TOKEN && export CAIDO_TOKEN`, then paste and
   press Enter. Or save it in a file only you can read (`chmod 600`) and pass
   `--token-file <file>`.
3. Pull the requests for the host you are working on:

   ```bash
   python3 tools/caido_pull.py --filter 'req.host.eq:"shop.example.com"' \
       --since 2026-10-01 --redact-locally --out shop.json
   ```

   `--filter` is any HTTPQL query, as in Caido's search bar. `--since` and `--until` take a
   date or time (UTC unless you give a zone). `--caido` is Caido's address if it is not
   `http://127.0.0.1:8080`. `--redact-locally` replaces cookies, authorization headers and
   other secrets before the file is written, so they never land on your disk;
   AttackLedger redacts them again when it imports the file.
4. Upload it, or add `--upload` to the same command to send it straight away:
   `--upload https://attackledger.example.com/api --engagement "<engagement name>" --al-email you@example.com`.
   The address is the one you open in the browser with `/api` added. The engagement is the
   name in the **Engagements** list (or its number). The tool asks for your AttackLedger
   password, signs in as you, uploads the file and signs out. It then prints the same
   counts as the Import tab.

What it sends where: the Caido token goes only to your Caido, never to AttackLedger, and
never appears in the file or in what the tool prints. The file goes only to the
AttackLedger address you give. The tool uses no proxy from your environment (your proxy
may be Caido itself, which would record the token) and follows no redirects. If Caido
answers in a shape the tool does not know (Caido's API changes between releases), it
stops and says so without writing a file; use Caido's own export above until the tool is
updated. The details are in [`IMPORT.md`](IMPORT.md), "Pull from Caido".

**A browser**, HAR (Chrome, Edge or Firefox):

1. Open the developer tools (F12), the **Network** tab, and tick **Preserve log** (Firefox:
   **Persist Logs**, in the gear menu).
2. Use the application.
3. Chrome and Edge: the **Export HAR** button (a downward arrow) in the Network tab's
   toolbar, or right-click any request, **Save all as HAR**. Firefox: right-click any
   request, **Save All As HAR**.

### Upload it

1. **Import** tab, **Export file**: choose the file. **Format** can stay on **Detect from
   the file**.
2. **Import**. The result says how many entries reached the inbox, how many were refused as
   out of scope, how many were duplicates and how many were unreadable.
3. **Rows not imported** lists the others by row number. Out-of-scope rows are listed by
   host only, and only in the batch (the change history records just a count). A row is a
   duplicate, and is not added again, only when it is an exact copy of an entry already in
   the inbox (or earlier in the same file): the same method, URL and status, and the same
   request and response bytes after redaction. A page you loaded twice usually makes two
   entries, because the server's answer differs, if only in its `Date` header, which
   changes every second.
4. If you upload a file you already imported, AttackLedger stops and says "This file was
   already imported on <date> by <who>". Choose **Import it again** only if you mean to.

The uploaded file itself is not kept, only its SHA-256 (under **Imported files**).

## 6. Map entries, mark items done, or mark them not applicable

### Map imported entries

1. The **Inbox** on the **Import** tab shows the entries **To map**. Filter by host,
   status, file or a word in the URL.
2. Click an entry to open it. **View request** and **View response** show the stored bytes,
   after redaction.
3. Under **Map to checklist items**, tick the suggested items that the entry is evidence for
   (each suggestion says why it was made), or pick others in **Another item**. Items on a
   lane that is not open yet say "(opens the lane)": choosing one opens it.
4. Optional: a **Note**, which goes into the evidence summary.
5. To mark the chosen items done in the same step, tick **Mark these items done**. It is
   off by default, because one request is often only part of a test. Otherwise the items
   stay open with evidence attached; the lane panel counts them as waiting to be marked
   done.
6. To map several entries of the same host to the same items at once, select them in the
   inbox first, then tick **Also map the other selected entries**.
7. **Add to the ledger**. Each entry and item pair becomes one evidence entry, with the
   source "import" and the tool's name. Mapping the same entry to the same item again adds
   nothing.

Entries that are not evidence of anything (assets, noise): **Dismiss**, with a reason. A
dismissal is recorded and can be undone: show **Dismissed**, open the entry, **Restore**.

### Mark items done

In the lane panel, **Mark done** on the item. It needs at least one evidence entry on that
item.

### Mark items not applicable

1. **Not applicable** on the item.
2. Write why it does not apply to this host, for example "The host has no login, so session
   tests do not apply." The reviewer reads it, and so does the client in the report.
3. **Mark not applicable**.

For many items at once: **Mark the N open items not applicable…** above the checklist
applies one reason to every open item without evidence, after you review the list.

**Reopen** puts an item back to open. Any change to a receipted lane makes its receipt
void until a reviewer signs it again.

## 7. Ask a reviewer to sign

When every item is done or not applicable, the lane panel says "a reviewer can sign and
close the lane", and the ledger cell says **ready to sign**. AttackLedger sends no
notifications: tell your reviewer which lanes are ready (host and lane name).

The reviewer opens the lane, reads its evidence, ticks **I reviewed this lane's evidence.
Only a person closes a lane.**, and chooses **Sign and close lane**. Their browser signs the
receipt with a key that never leaves it. Then:

- If the engagement has **separation of duties** on, whoever attached or mapped evidence on
  a lane cannot sign it. Ask someone else.
- If the reviewer's sign-off is refused, the panel lists each item that still needs evidence
  or a reason, and the list follows your changes.
- If the lane depends on another lane (**Needs …**), that lane must be receipted first.
- Once signed, the cell shows **Receipted** and the receipt's hash. If the receipt could not
  be timestamped, the panel says "Not timestamped" and the reviewer can use
  **Timestamp now** later.

## 8. What the client sees, and how they verify it

The client (and any auditor) has the **Viewer** role. They can read everything on the
engagement but change nothing: the coverage ledger, every evidence entry and its stored
bytes, the import inbox and the imported entries, the controls, the change history and the
report. So write notes and N/A reasons for that reader, and remember that whatever you
import is visible to them, after redaction.

They open the engagement on the **Report** tab:

- **Open printable report**, **Download HTML** and **Download JSON**: the same report,
  with every receipt, the evidence chain and the hashes needed to check them. Lanes not
  opened count as untested. The downloads are named after the engagement and its number,
  `attackledger-<engagement>-<n>.html` or `.json`, with the name in lower case and a hyphen
  for each space or other sign: for example `attackledger-lab-practice-1.html`.
- The **Verify** tab checks the report in the browser.

Anyone can check a downloaded report without AttackLedger and without an account:

1. Go to **https://attackledger.com/verify**.
2. Drop the report file (the JSON or HTML that AttackLedger exports) on the page, or choose
   it. The file is checked in the browser and never uploaded.
3. The page rebuilds each receipt from its items and evidence, checks every signature and
   timestamp, walks the evidence chain and recomputes the report's hash. **Verified** ("No
   check failed") means nothing was changed after the report was made. **Failed** names
   each check that failed.

The same check works offline with Python 3 and nothing else. **The same check, offline**,
on the **Verify** tab (and at the bottom of the **Report** tab) says how:

1. Get `verify_report.py` and the timestamp root it trusts,
   `digicert-trusted-root-g4.pem`, from attackledger.com: the page links to both.
2. Save the report next to them and run the command the page shows, with your file's
   name:

   ```bash
   python3 -I verify_report.py attackledger-lab-practice-1.html --tsa-root digicert-trusted-root-g4.pem
   ```

   (The page's command names the file `report.json`, or `attackledger-report.html` on the
   Report tab; the download is called `attackledger-<engagement>-<n>.html` or `.json`.)
   It ends with `Verified.` or names each check that failed.
3. Or use this server's copy: **download attackledger-verifier.zip** under the command. It
   holds the script with a `tsa-roots/` folder beside it; unzip it, put the report in the
   `attackledger-verifier` folder and run the command there without `--tsa-root`. A copy
   from the tester's own server proves less than the independent one, so the page shows its
   SHA-256: compare it with the copy from attackledger.com (`shasum -a 256 verify_report.py`
   on each) before relying on it.

For high assurance, the client compares each signer's key fingerprint in the report with
the one the signer gives them directly.
