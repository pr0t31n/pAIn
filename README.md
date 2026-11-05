# pAIn — AI Pipeline Prompt-Injection Red-Team Tool

> [!CAUTION]
> **Under Development — Untested.** This tool has not been validated in production engagements. Features may be incomplete, unstable, or produce unreliable results. Do not rely on its output for deliverables without independent verification.

**pr0t31n toolkit — authorized engagements only.**

pAIn is a comprehensive AI security testing tool that combines three attack
vectors: adversarial file-based prompt injection, vulnerability scanning via
nuclei AI templates, and LLM jailbreak testing via NVIDIA garak. It tests AI
file-ingestion pipelines (transcription, classification, chat) for resilience
against adversarial prompts embedded in file metadata, text layers, and audio
content, scans AI service endpoints for known vulnerabilities, and probes LLM
APIs for jailbreak susceptibility.

pAIn operates standalone or as a Crucible-managed tool, where it is
automatically triggered when Scattershot3, Fracture, or Siphon discover AI
services during an engagement.

---

> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/pain)** — detailed features, CLI reference, findings catalogue, and integration guides.

---

## How it works

### 1. File-Based Prompt Injection (built-in)

1. **Generate** — for each format x payload category x embedding strategy,
   pAIn produces a file containing a unique `PAIN_<hex>` canary token inside
   the appropriate injection surface (EXIF field, document metadata, audio
   tag, visible text overlay, spoken audio, etc.).

2. **Submit** — each file is POSTed to the target AI endpoint as a multipart
   upload, mimicking a real user submission. Supports both direct API
   endpoints (bearer/API key auth) and web applications (form-based login
   with CSRF, cookie auth).

3. **Detect** — if the AI's response contains the canary token, the embedded
   instruction was followed rather than the file being transcribed/classified.
   Optionally polls a separate verify URL for stored-result injection.

4. **Report** — results are written as `pain_results.json` (raw) and
   `findings.json` (pr0t31n universal schema, OWASP LLM01:2025 mapped).

### 2. Nuclei AI Template Scan (`--nuclei-ai`)

Orchestrates [ProjectDiscovery nuclei](https://github.com/projectdiscovery/nuclei)
with AI-specific vulnerability templates targeting AI/ML platforms:

- **Tags scanned**: `ai`, `llm`, `ollama`, `gradio`, `mlflow`, `vllm`,
  `triton`, `bentoml`, `litellm`, `torchserve`, `huggingface`, `langflow`
- **Template coverage**: ~148 templates across technology detection, known
  CVEs, and DAST checks
- Findings merge into the same `findings.json` alongside prompt injection results

### 3. NVIDIA Garak LLM Vulnerability Scan (`--garak`)

Orchestrates [NVIDIA garak](https://github.com/NVIDIA/garak) for LLM-specific
vulnerability testing:

- **666+ jailbreak probes** targeting prompt injection, data leakage, toxicity,
  hallucination, and encoding-based bypasses
- Targets the AI endpoint as a REST model
- Selective probe execution via `--garak-probes`
- Findings merge into `findings.json`

---

## Crucible Managed Mode

When launched by Crucible (`CRUCIBLE_MANAGED=1`), pAIn emits real-time protocol
tokens for dashboard integration:

| Token | Purpose |
|-------|---------|
| `__CRUCIBLE_LOG__` | Timestamped log messages |
| `__CRUCIBLE_ERR__` | Error messages |
| `__CRUCIBLE_STATUS__` | Phase/progress tracking |
| `__CRUCIBLE_FINDING__` | Real-time finding emission |

**pAIn is action-item-driven** — it does not appear in Crucible's project
wizard. Instead, it runs automatically when an `ai_discovered` action item is
created by another tool:

### AI Detection Pipeline

```
SS3/Fracture/Siphon discover AI service
  → emit __CRUCIBLE_TARGET__ with AI metadata
  → emit __CRUCIBLE_ACTION_ITEM__ {category: "ai_discovered"}
    → Crucible action engine routes to pAIn
      → PainAdapter builds CLI with auth passthrough
        → pAIn runs prompt injection + nuclei AI + garak
          → findings stream back via __CRUCIBLE_FINDING__
```

**Auth passthrough** — Crucible's PainAdapter forwards all authentication
credentials from the project configuration:

| Auth Method | CLI Flags |
|-------------|-----------|
| Bearer token | `--auth-method bearer --bearer-token <token>` |
| Cookie | `--auth-method cookie --cookie <value>` |
| API key | `--api-key <key>` |
| Basic auth | `--auth-method basic --bearer-token <user:pass>` |
| Form login | `--login-url <url> --username <user> --password <pass>` |
| Custom header | `--auth-header Key:Value` |

Configure pAIn settings in the project **Settings tab** after project creation.

---

## Payload categories

| Category          | What it tests                                             |
|-------------------|-----------------------------------------------------------|
| `task_hijack`     | AI abandons transcription/classification entirely         |
| `prefix_inject`   | AI prepends canary to otherwise-normal output             |
| `classify_override` | AI returns injected class label instead of real one     |
| `system_probe`    | AI reveals its system prompt / operating instructions     |
| `authority_claim` | AI follows instruction claiming special/admin authority   |

---

## Supported formats and injection strategies

| Format | Strategy                  | Requires           |
|--------|---------------------------|--------------------|
| PDF    | Document info metadata    | reportlab          |
| PDF    | Visible body text         | reportlab          |
| PDF    | Hidden text layer         | reportlab          |
| PDF Text | Visible body text (alt) | reportlab          |
| DOCX   | Document body text        | stdlib (zipfile)   |
| ZIP    | Contained payload files   | stdlib (zipfile)   |
| PNG    | tEXt / iTXt metadata chunk | Pillow            |
| PNG    | EXIF fields               | Pillow + piexif    |
| PNG    | Text overlay (OCR surface)| Pillow             |
| JPG    | EXIF (ImageDescription / UserComment) | Pillow + piexif |
| JPG    | Text overlay              | Pillow             |
| HEIF   | EXIF fields               | Pillow + pillow-heif + piexif |
| HEIF   | Text overlay              | Pillow + pillow-heif |
| WAV    | LIST INFO chunk           | stdlib only        |
| WAV    | ID3 tags                  | mutagen            |
| WAV    | Spoken audio content      | espeak             |
| MP3    | ID3 tags (TIT2/USLT/COMM) | mutagen + ffmpeg   |
| MP3    | Spoken audio content      | espeak + ffmpeg    |
| FLAC   | Vorbis comment tags       | mutagen + ffmpeg   |
| FLAC   | Spoken audio content      | espeak + ffmpeg    |
| ALAC   | MP4 / iTunes tags         | mutagen + ffmpeg   |
| AAC    | MP4 / iTunes tags         | mutagen + ffmpeg   |
| AAC    | Spoken audio content      | espeak + ffmpeg    |
| OGG    | Vorbis comment tags       | mutagen + ffmpeg   |

---

## Requirements

- Python 3.10+
- `ffmpeg` (system package) — required for MP3, FLAC, ALAC, AAC, OGG generation
- `espeak` / `espeak-ng` (optional) — spoken-payload audio injection tests
- `nuclei` (optional) — required for `--nuclei-ai` AI template scanning
- `garak` (optional) — required for `--garak` LLM vulnerability testing

```
pip install requests Pillow piexif reportlab mutagen pillow-heif colorama
pip install garak                          # optional — NVIDIA garak
```

---

## Installation

```bash
python3 /opt/pr0t31n/pAIn/install.py   # installs system + Python deps
```

---

## Usage

### Basic file injection testing

```bash
# Submit test files to a target API
python3 pain.py --target config.json

# Bare URL with API key
python3 pain.py --target https://api.example.com/analyze \
                --api-key sk-abc123 \
                --file-field file \
                --resp-field text

# Generate files only (review before use)
python3 pain.py --dry-run --output ./test_files

# Restrict to specific formats and categories
python3 pain.py --target config.json \
                --formats pdf,png,mp3 \
                --categories task_hijack,prefix_inject

# Test all 4 payload variants per category (more thorough)
python3 pain.py --target config.json --all-variants

# List available formats and categories
python3 pain.py --list
```

### Web application authentication

```bash
# Form-based login (username/password with CSRF handling)
python3 pain.py --target https://app.host/upload \
                --login-url https://app.host/login \
                --username admin --password s3cr3t

# Pre-authenticated session cookie
python3 pain.py --target https://app.host/upload \
                --cookie 'session=abc123; csrf=def456'

# Custom auth header
python3 pain.py --target https://api.host/analyze \
                --auth-header "X-Custom-Auth:secret-token-value"
```

### Stored-result verification

```bash
# Poll a separate URL after upload to check for stored injection
python3 pain.py --target https://app.host/upload \
                --verify-url https://app.host/results \
                --verify-delay 5
```

### Whisper / transcription mode

```bash
# Detect stored verbatim transcription of injected spoken text
python3 pain.py --target https://api.host/transcribe \
                --formats wav,mp3 --whisper-mode \
                --verify-url https://api.host/jobs/latest
```

### Nuclei AI template scanning

```bash
# Run nuclei with AI-specific templates against a target
python3 pain.py --target https://ai-service.host:11434 --nuclei-ai

# Combine with file injection testing
python3 pain.py --target https://ai-service.host/api/analyze \
                --api-key sk-abc123 --nuclei-ai
```

### Garak LLM vulnerability testing

```bash
# Run full garak probe suite against an LLM endpoint
python3 pain.py --target https://ai-service.host/v1/chat/completions --garak

# Run specific garak probes only
python3 pain.py --target https://ai-service.host/v1/chat/completions \
                --garak --garak-probes "encoding,dan,glitch"

# Combined: file injection + nuclei + garak
python3 pain.py --target https://ai-service.host/api/analyze \
                --api-key sk-abc123 --nuclei-ai --garak
```

### Crucible managed mode

```bash
# Launched by Crucible PainAdapter (not typically run manually)
CRUCIBLE_MANAGED=1 python3 pain.py \
    --target https://10.0.0.50:11434 \
    --ai-type api --model llama3 \
    --auth-method bearer --bearer-token sk-abc123 \
    --output-dir /path/to/project/pain \
    --nuclei-ai --garak
```

### Target config file (`config.json`)

```json
{
    "endpoint":        "https://api.example.com/v1/analyze",
    "auth": {
        "type":  "bearer",
        "token": "sk-YOUR_KEY"
    },
    "file_field":      "file",
    "extra_fields":    { "model": "whisper-1" },
    "response_format": "json",
    "response_field":  "text",
    "timeout":         30,
    "verify_ssl":      true,
    "login_url":       null,
    "verify": {
        "url":   null,
        "delay": 3
    }
}
```

`auth.type` options: `bearer`, `apikey`, `cookie`, `form`, `none`

---

## CLI Reference

### Target and submission

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | (required) | Config JSON file path or bare `http(s)://` endpoint URL |
| `--formats` | `all` | Comma-separated: `pdf,pdf_text,docx,zip,png,jpg,heif,wav,mp3,flac,alac,aac,ogg` |
| `--categories` | `all` | Comma-separated: `task_hijack,prefix_inject,classify_override,system_probe,authority_claim` |
| `--output` | `./pain_output` | Output directory |
| `--dry-run` | off | Generate test files without submitting |
| `--all-variants` | off | Test all payload template variants (default: 1 per category) |
| `--file-field` | `file` | Multipart form field name for file upload |
| `--resp-field` | `text` | JSON field in response containing AI output |
| `--timeout` | `30` | HTTP request timeout (seconds) |
| `--no-ssl-verify` | off | Disable SSL certificate verification |
| `--list` | off | List available formats and payload categories |

### Authentication

| Flag | Description |
|------|-------------|
| `--api-key` | API key / Bearer token for direct API endpoints |
| `--auth-method` | Authentication method: `none`, `bearer`, `cookie`, `apikey`, `basic`, `custom` |
| `--bearer-token` | Bearer token (alternative to `--api-key`) |
| `--auth-header` | Full auth header as `Key:Value` |
| `--login-url` | Login page URL (triggers form-based session authentication) |
| `--upload-url` | Upload endpoint URL (if different from `--target`) |
| `--username` | Username for form-based login |
| `--password` | Password for form-based login |
| `--csrf-field` | Hidden CSRF input field name (default: `csrf_token`) |
| `--cookie` | Pre-authenticated session cookie string (skips login form) |
| `--header` | Extra HTTP header (repeatable) |

### Verification and detection

| Flag | Default | Description |
|------|---------|-------------|
| `--verify-url` | none | URL to poll after upload to check for stored canary |
| `--verify-delay` | `3` | Seconds to wait before polling verify URL |
| `--whisper-mode` | off | Detect verbatim storage of injected spoken text as `STORED_TEXT_INJECTION` |

### Crucible integration

| Flag | Default | Description |
|------|---------|-------------|
| `--ai-type` | `auto` | AI target type: `auto`, `chat`, `file-upload`, `api`, `transcription` |
| `--model` | none | Target model identifier |
| `--output-dir` | none | Output directory (Crucible compatibility alias for `--output`) |

### Third-party tool orchestration

| Flag | Description |
|------|-------------|
| `--nuclei-ai` | Run nuclei with AI-specific vulnerability templates against target |
| `--garak` | Run garak LLM vulnerability scanner against target |
| `--garak-probes` | Comma-separated garak probe names (default: all probes) |

---

## Output files

```
pain_output/
├── findings.json          # pr0t31n universal schema (OWASP LLM01:2025)
├── pain_results.json      # full raw results for all tests
├── meta.json              # universal run metadata
├── summary.json           # aggregated statistics
├── test_files/            # generated adversarial files
│   ├── task_hijack_pdf_v00_pdf_meta.pdf
│   ├── task_hijack_docx_v00_docx_body.docx
│   └── ...
├── responses/             # raw API responses per test
│   ├── task_hijack_pdf_v00_pdf_docinfo_metadata.json
│   └── ...
├── nuclei_ai_results.json # nuclei JSONL output (when --nuclei-ai)
└── garak_results/         # garak output directory (when --garak)
    └── garak_report.jsonl
```

---

## Severity mapping

| Verdict              | Severity | Meaning                                            |
|----------------------|----------|----------------------------------------------------|
| `FULL_TASK_HIJACK`   | CRITICAL | AI output is only the canary — primary task abandoned |
| `PARTIAL_INJECTION`  | HIGH     | Canary present but task output also produced       |
| `STORED_TEXT_INJECTION` | HIGH  | Canary found in stored/indexed result, not in immediate response |
| `RESILIENT`          | INFO     | No canary detected — injection had no effect       |

---

## Remediation guidance

When findings are reported, the following controls should be evaluated:

1. **Strip file metadata** before passing extracted text to the LLM context
2. **Fixed system prompt** with an explicit instruction that file content cannot override operating instructions
3. **Context isolation** — file content processed in a separate context from system instructions
4. **Output validation** — validate AI response against expected schema; flag unexpected tokens
5. **Multimodal sanitization** — for image/audio inputs, use structured extraction (not raw OCR text passed directly to LLM)
6. **Anomaly alerting** — log and alert on responses containing `PAIN_*` or other unexpected marker tokens

---

## Third-Party Credits

pAIn orchestrates the following third-party tools for AI security testing. These
tools are not bundled with pAIn and must be installed separately.

| Tool | Developer | License | Repository |
|------|-----------|---------|------------|
| nuclei | ProjectDiscovery | MIT License | [github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) |
| garak | NVIDIA Corporation | Apache License 2.0 | [github.com/NVIDIA/garak](https://github.com/NVIDIA/garak) |

---

## Integration

pAIn produces `findings.json` in the pr0t31n universal schema. Findings can
be imported directly into Prometheus for unified reporting alongside Fracture,
Siphon, and other tool outputs.

**Crucible integration**: pAIn is registered as a Crucible-managed tool (key
`PI`, domain `ai`). Crucible's action engine automatically routes
`ai_discovered` action items to pAIn when AI services are detected by
Scattershot3, Fracture, or Siphon during an engagement.

**Codex**: Full documentation including features, CLI reference, finding
nomenclature, and integration details available on the Codex wiki.

OWASP mapping: **LLM01:2025 — Prompt Injection**
NIST AI RMF: GOVERN 1.7, MANAGE 2.4
