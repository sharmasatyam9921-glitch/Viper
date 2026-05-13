# VIPER → OSCP/Internal-Pentest Capability Plan

VIPER's existing strength is external bug-bounty: web recon, web exploitation, brute force, CVE lookup. The gaps for OSCP-style internal pentesting are: **Active Directory**, **Linux/Windows privesc**, **lateral movement / pivoting**, **credential dumping**.

**STATUS:** All 5 phases built and tested (108 unit tests passing). VIPER can now drive a full HTB Pro Lab / OSCP-style internal episode autonomously via `agents.LateralAgent`.

---

## What already exists (no work needed)

| Module | Coverage |
|---|---|
| `tools/metasploit.py` | MSF subprocess interface |
| `tools/tunnel_manager.py` | chisel + ngrok tunnel management |
| `tools/kali_tools.py` | async wrappers for nmap / hydra / curl / etc. |
| `tools/nmap_scanner.py`, `masscan_scanner.py` | port scanning |
| `core/phase_engine.py` | already has `POST_EXPLOIT` phase + tools registered |
| `agents/post_exploit.py` | stub class — **needs body** |

So the framework is in place. Missing pieces are the actual tool wrappers and skill prompts.

---

## Phase 1 — AD enumeration + privesc DB ✓ DONE

| File | Purpose |
|---|---|
| `core/skill_prompts/active_directory.py` | LLM workflow for AD attack: enumerate → kerberoast → asreproast → privesc → DCSync |
| `core/skill_prompts/linux_privesc.py` | LLM workflow for Linux privesc: enum → SUID/sudo/cap → kernel exploit → service abuse |
| `core/skill_prompts/windows_privesc.py` | LLM workflow for Windows privesc: token check → unquoted services → AlwaysInstallElevated → kernel |
| `tools/impacket_runner.py` | Subprocess wrappers for `GetUserSPNs`, `GetNPUsers`, `secretsdump`, `psexec`, `smbexec`, `wmiexec`, `ticketer` |
| `pentest/__init__.py` | Package init |
| `pentest/gtfobins_db.py` | Local lookup table: SUID binary or sudoer entry → escalation one-liner |
| `pentest/kernel_exploits_db.py` | Local lookup: Linux/Windows kernel version → matching public exploits |
| `pentest/ad_enum.py` | Orchestrator: SMB null session, LDAP enum, RID cycling, Kerberos pre-auth, GPP password hunt |
| `tests/test_pentest_phase1.py` | Unit tests for Phase 1 modules |

**Acceptance criteria** for Phase 1:
- `from pentest import ad_enum, gtfobins_db, kernel_exploits_db` works
- `ImpacketRunner.kerberoast(target, user, password, domain)` returns dict with TGS hashes (or stubbed result if impacket not installed)
- `gtfobins_db.lookup("find")` returns at least 3 escalation paths
- `kernel_exploits_db.lookup_linux("4.4.0-116-generic")` returns DirtyCOW + others
- 11+ unit tests passing

---

## Phase 2 — Privesc enumerators ✓ DONE

| File | Purpose |
|---|---|
| `tools/linpeas_runner.py` | Auto-deploy linpeas (download from GitHub, scp to target via SSH/SMB), run, parse output, return ranked findings |
| `tools/winpeas_runner.py` | Same for winpeas |
| `pentest/sudo_analyzer.py` | Parse `sudo -l` output → cross-reference gtfobins_db → ranked escalation paths |
| `pentest/cap_analyzer.py` | Parse Linux capabilities (`getcap -r`) → escalation paths |
| `pentest/service_analyzer.py` | Windows: parse `sc query` / `tasklist /svc` → unquoted paths, weak permissions, AlwaysInstallElevated |

---

## Phase 3 — BloodHound integration ✓ DONE

| File | Purpose |
|---|---|
| `tools/bloodhound_runner.py` | Drop SharpHound onto Windows target, run collection, ingest .json into local Neo4j |
| `pentest/bh_queries.py` | Pre-canned Cypher queries: kerberoastable users, AS-REP roastable, shortest path to DA, DCSync rights, unconstrained delegation |
| `docker/bloodhound-compose.yml` | Optional Neo4j + BloodHound CE Docker stack |

---

## Phase 4 — Pivoting / tunneling ✓ DONE

`tools/tunnel_manager.py` already exists for chisel/ngrok. Extend with:

| File | Purpose |
|---|---|
| `pentest/ligolo_runner.py` | ligolo-ng tunnel manager (modern replacement for chisel for layer-3 pivoting) |
| `pentest/socks_proxy.py` | proxychains-style SOCKS chain config generator |
| `pentest/port_forward.py` | SSH local/remote port-forward helper |

---

## Phase 5 — Orchestration + post-exploit agent ✓ DONE

| File | Purpose |
|---|---|
| `agents/post_exploit.py` | Stub-free. Exposes `analyze_*_foothold()`, `enumerate_ad()`, `collect_bloodhound()`, `analyze_bloodhound_dump()`, `kerberoast()`, `asreproast()`, gated `secretsdump()`/`psexec()`/`ssh_port_forward()`/`start_ligolo_proxy()` |
| `agents/lateral_agent.py` | NEW. Autonomous campaign driver. State machine: ENUMERATE_HOST → ANALYZE_PRIVESC → EXECUTE_PRIVESC → DETECT_AD → AD_ENUM → PRE_AUTH_ATTACKS → AUTH_ATTACKS → CRED_DUMP → LATERAL_HOP. Two modes: deterministic (heuristic rules) and llm (model_router-driven). Halts on 2 consecutive failures. Approval-gated through PostExploitAgent. |
| `core/models.py` | Phase enum gained `LATERAL` |
| `core/phase_engine.py` | `PHASE_TOOLS["LATERAL"]` registers ad_enum, bloodhound, sharphound, kerberoast, asreproast, secretsdump, psexec, wmiexec, smbexec, ticketer, ligolo, chisel, ssh_forward, proxychains, etc. POST_EXPLOIT entries gained linpeas/winpeas/sudo_analyze/cap_analyze/service_analyze/gtfobins_lookup/kernel_exploit_lookup |
| `agents/__init__.py` | Re-exports `PostExploitAgent`, `LateralAgent`, `FootholdInfo`, `CredentialBundle`, `CampaignStep`, `LateralCampaign`, `LateralState` |

---

## What VIPER will be able to do after all 5 phases

**Initial foothold** (already): web vuln, brute force, CVE exploit
↓
**Privesc** (Phase 1+2): linpeas/winpeas → gtfobins lookup → kernel exploit → sudo abuse
↓
**AD enumeration** (Phase 1+3): SMB/LDAP enum → BloodHound → identify attack paths
↓
**AD attack** (Phase 1+5): kerberoast → crack offline → reuse cred → DCSync → domain admin
↓
**Lateral movement** (Phase 4+5): ligolo tunnel → psexec/wmiexec to next host → repeat

**This is HTB Pro Lab / OffSec PG / internal red-team capability.** Still NOT exam-legal (OffSec restricts auto-tooling), but useful for everything else.

---

## Out of scope (won't build)

- **Buffer overflow / ROP** — exam removed this in 2023; not worth building
- **Custom shellcode generation** — msfvenom suffices, already accessible via `tools/metasploit.py`
- **Phishing infrastructure** — already exists at `core/skill_prompts/phishing.py`
- **C2 frameworks** (Sliver, Cobalt Strike) — out of bug-bounty/research scope
- **Mimikatz on disk** — `secretsdump.py` (Impacket) covers same ground without dropping mimikatz binary

---

## Risk + ethics rails

All new modules respect existing VIPER rails:
- `core/roe_engine.py` scope check before any active probe
- `core/approval_gate.py` for credential-dump or exploit execution
- `core/guardrails.py` target validation
- All findings persisted via `core/chain_writer.py`
- Audit log to `logs/`

Phase 1 modules ship **disabled by default** (off in `core/phase_engine.py` POST_EXPLOIT auto-tools list) — must be explicitly enabled per-engagement.
