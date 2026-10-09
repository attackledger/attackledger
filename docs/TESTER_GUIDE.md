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

Only owners change the rules. Read the program's policy too; AttackLedger enforces its
own copy of the rules on its own traffic, not on yours.

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
| **Needs …** | The lane depends on another lane on the same host (for example, every WSTG lane needs *Information gathering*). |

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
   host only; nothing else about them is stored. If some rows were already in the inbox
   (for example, the same file imported twice), the result warns you and lists them as
   **Already in the inbox**; they are not added again.

The uploaded file itself is not kept, only its SHA-256 (under **Imported files**).

## 6. Map entries, mark items done, or mark them not applicable

### Map imported entries

1. The **Inbox** on the **Import** tab shows the entries **To map**. Filter by host,
   status, file or a word in the URL.
2. Click an entry to open it. **View request** and **View response** show the stored bytes,
   after redaction.
3. Under **Map to checklist items**, tick the suggested items that the entry is evidence for
   (each suggestion says why it was made), or pick others in **Another item**. A lane must
   be open on the entry's host first; if none is, open one on the **Ledger** tab.
4. Optional: a **Note**, which goes into the evidence summary.
5. To mark the chosen items done in the same step, tick the option to mark them done.
   Otherwise they stay open with evidence attached, and you mark them done in the lane.
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
  opened count as untested.
- The **Verify** tab checks the report in the browser.

Anyone can check a downloaded report without AttackLedger and without an account:

1. Go to **https://attackledger.com/verify**.
2. Drop the report file (the JSON or HTML that AttackLedger exports) on the page, or choose
   it. The file is checked in the browser and never uploaded.
3. The page rebuilds each receipt from its items and evidence, checks every signature and
   timestamp, walks the evidence chain and recomputes the report's hash. **Verified** ("No
   check failed") means nothing was changed after the report was made. **Failed** names
   each check that failed.

The same check works offline with Python 3: `python3 tools/verify_report.py report.json`
(the script is in the AttackLedger repository, or downloaded with **Download
verify_report.py** on the **Verify** tab). For high assurance,
the client compares each signer's key fingerprint in the report with the one the signer gives
them directly.
