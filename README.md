# pAIn — AI Pipeline Prompt-Injection Red-Team Tool

> [!CAUTION]
> **Under Development — Untested.** This tool has not been validated in production engagements. Features may be incomplete, unstable, or produce unreliable results. Do not rely on its output for deliverables without independent verification.

**pr0t31n toolkit — authorized engagements only.**

pAIn tests AI file-ingestion pipelines (transcription, classification) for
resilience against adversarial prompts embedded in file metadata, text layers,
and audio content.  It generates canary-bearing test files across 10 file
formats, submits them to the target API, and classifies each outcome.

---

## How it works

1. **Generate** — for each format × payload category × embedding strategy,
   pAIn produces a file containing a unique `PAIN_<hex>` canary token inside
   the appropriate injection surface (EXIF field, document metadata, audio
   tag, visible text overlay, spoken audio, etc.).

2. **Submit** — each file is POSTed to the target API endpoint as a
   multipart upload, mimicking a real user submission.

3. **Detect** — if the AI's response contains the canary token, the embedded
   instruction was followed rather than the file being transcribed/classified.

4. **Report** — results are written as `pain_results.json` (raw) and
   `findings.json` (pr0t31n universal schema, OWASP LLM01:2025 mapped).

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

```
pip install requests Pillow piexif reportlab mutagen pillow-heif colorama
```

---

## Installation

```bash
sudo bash /tmp/deploy_pain.sh
python3 /opt/pr0t31n/pAIn/install.py   # installs system + Python deps
```

---

## Usage

### Basic usage

```bash
# Submit test files to a target API
python3 pain.py --target config.json

# Bare URL with API key
python3 pain.py --target https://api.example.com/analyze \
                --api-key sk-abc123 \
                --file-field file \
                --resp-field text

# Generate files only — no submission (review before use)
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
    "verify_ssl":      true
}
```

`auth.type` options: `bearer`, `apikey`, `none`

---

## Output files

```
pain_output/
├── findings.json          # pr0t31n universal schema (OWASP LLM01:2025)
├── pain_results.json      # full raw results for all tests
├── test_files/            # generated adversarial files
│   ├── task_hijack_pdf_v00_pdf_meta.pdf
│   ├── task_hijack_pdf_v00_pdf_content.pdf
│   └── ...
└── responses/             # raw API responses per test
    ├── task_hijack_pdf_v00_pdf_docinfo_metadata.json
    └── ...
```

### Severity mapping

| Verdict          | Severity | Meaning                                        |
|------------------|----------|------------------------------------------------|
| `FULL_TASK_HIJACK` | CRITICAL | AI output is only the canary — primary task abandoned |
| `PARTIAL_INJECTION` | HIGH   | Canary present but task output also produced   |
| `RESILIENT`      | INFO     | No canary detected — injection had no effect   |

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

## Integration

pAIn produces `findings.json` in the pr0t31n universal schema.  Findings can
be imported directly into Prometheus for unified reporting alongside Fracture,
Siphon, and other tool outputs.

OWASP mapping: **LLM01:2025 — Prompt Injection**
NIST AI RMF: GOVERN 1.7, MANAGE 2.4
