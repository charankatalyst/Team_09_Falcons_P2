# Operation Shadow R2 - Incident Summary

**Data exfiltration: UNCONFIRMED** (basis: N-05, N-04 are access/capability, not transfer)

## Timeline

| ID | Time | Event | Type | Strength | Stage | Evidence gap |
|---|---|---|---|---|---|---|
| N-01 | 08:41 | Suspicious payroll-themed email delivered to Mira | FACT | 2/3 | Delivery | Full headers and attachments/links not provided |
| N-02 | 08:44 | Successful sign-in from unfamiliar IP and new browser | FACT | 2/3 | Initial access | No proof the sign-in was made by the email sender |
| N-03 | 08:45 | MFA push approved; user denies initiating it | FACT | 3/3 | Credential / MFA abuse | Approver device and prompt source not provided |
| N-04 | 08:47 | External mailbox forwarding rule created | FACT | 3/3 | Persistence | Rule destination and match conditions not provided |
| N-05 | 08:49 | File portal records three document previews under Mira's session | FACT | 1/3 | Collection (access only) | No confirmed download event; documents not identified |
| N-06 | 08:51 | Sign-in attempt from usual office network fails | FACT | 1/3 | Possible lockout | Failure reason not provided |
| N-07 | 08:54 | User reports the email to IT | FACT | 0/3 | Response | none |
| N-08 | 08:56 | Security team disables active sessions and blocks sign-in pending identity verification | FACT | 0/3 | Response | none |
| N-09 | 09:02 | Mailbox rule removed; investigation remains open | FACT | 0/3 | Response | none |

## Strongest indicators
- N-03 MFA push approved; user denies initiating it (Credential / MFA abuse)
- N-04 External mailbox forwarding rule created (Persistence)
- N-01 Suspicious payroll-themed email delivered to Mira (Delivery)

## Likely attack path (hypothesis)
Delivery -> Initial access -> Credential / MFA abuse -> Persistence -> Collection (access only) -> Possible lockout

## Assumptions to verify

| Assumption | Basis | Would confirm it |
|---|---|---|
| Phish led to credential theft | Timing only (3 min); order does not prove causation | Headers, link click and credential-submission logs |
| Attacker obtained the MFA approval (prompt fatigue or social engineering) | User denial plus unfamiliar sign-in | Approver device/IP and prompt logs |
| Forwarding rule was meant to exfiltrate mail | External destination rule created minutes after sign-in | Rule destination and forwarded-message logs |
| Previews were attacker reconnaissance | Previews followed the suspicious session | Session/IP attribution of the previews |
| Office sign-in failed because the attacker changed credentials | Failure soon after compromise | Failure reason in identity logs |

## Prioritized response
- [x] **P0** Disable active sessions and block sign-in pending identity verification
- [x] **P0** Remove external forwarding rule(s); record destination first for evidence
- [ ] **P1** Preserve logs (identity, mail, file portal, proxy) before retention rolls over
- [ ] **P1** Verify Mira's identity out-of-band; then reset password and re-register MFA
- [ ] **P1** Hunt: forwarded mail, downloads and egress in the exposure window (see evidence gaps)
- [ ] **P2** Audit other inbox rules, delegates, OAuth grants and recovery settings
- [ ] **P2** Purge the phishing email from other mailboxes; block sender/domain
- [ ] **P3** Decide on notification only after exfiltration is confirmed or ruled out
- [ ] **P3** Enable number matching / phishing-resistant MFA; staff awareness note

## Evidence needed before claiming exfiltration
1. File-portal download/export logs for the 08:44 session (a preview is not a download)
2. Mail transport logs for messages matching the forwarding rule between creation and removal, plus its destination
3. Proxy / DLP / network egress logs for the user and session IP during the window
4. Correlation of the previews and rule creation to the same session ID/IP as the unfamiliar sign-in
5. Identity and sensitivity of the previewed documents
6. Mira's statement that she did not preview those documents herself

Confidence: high that the session was unauthorized-looking, medium on attacker intent, low on any data loss.