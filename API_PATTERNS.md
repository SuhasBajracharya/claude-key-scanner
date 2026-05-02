# API Key Patterns Reference

This document details the regex patterns used to detect each API key type.

## Anthropic/Claude

**Prefixes:** `sk-ant-`

**Patterns:**
```regex
sk-ant-api\d{2}-[a-zA-Z0-9_-]{32,}      # Full key with API version
sk-ant-[a-zA-Z0-9_-]{32,}               # Simplified format
(?:ANTHROPIC_API_KEY|claude.*api[_-]?key)\s*[:=]\s*["\']?(sk-ant-[^"\'\s]+)  # In config
```

**Example:** `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`

## OpenAI/ChatGPT

**Prefixes:** `sk-`, `sk-proj-`

**Patterns:**
```regex
sk-proj-[a-zA-Z0-9_-]{32,}               # Organization project keys
(?:openai.*key|chatgpt.*key|gpt.*api[_-]?key|openai[_-]?api[_-]?key)\s*[:=]\s*["\']?(sk-[^"\'\s]+)  # In config
sk-[a-zA-Z0-9]{48,}(?:[a-zA-Z0-9_-]{0,})  # Legacy format
```

**Example:** `sk-proj-abc123...xyz789`

## Google Gemini/Vertex AI

**Prefixes:** `AIza`

**Patterns:**
```regex
AIza[0-9A-Za-z_-]{35}                    # Standard Gemini API key
(?:gemini.*key|google.*ai.*key)\s*[:=]\s*["\']?([aA][iI][zZ]a[0-9A-Za-z_-]{35})  # In config
```

**Example:** `AIzaSyDummy1234567890abcdefghijkl`

## Hugging Face

**Prefixes:** `hf_`

**Patterns:**
```regex
hf_[a-zA-Z0-9_-]{34,}                    # Standard HF token
(?:hugging.*face|hf[_-]?token)\s*[:=]\s*["\']?(hf_[a-zA-Z0-9_-]{34,})  # In config
```

**Example:** `hf_abcdefghijklmnopqrstuvwxyz123456`

## Cohere

**Patterns:**
```regex
(?:cohere.*key|cohere[_-]?api)\s*[:=]\s*["\']([\da-f-]{36})  # In config
```

**Example:** Typically UUID format

## DeepSeek

**Prefixes:** `sk-`

**Patterns:**
```regex
sk-[a-zA-Z0-9]{32,}
```

**Note:** Similar format to OpenAI tokens

## Azure OpenAI

**Pattern:**
```regex
(?:azure.*key|azure[_-]?openai.*key)\s*[:=]\s*["\']([\da-f]{32})
```

**Example:** 32-character hex string

## Replicate

**Prefixes:** `r8_`

**Patterns:**
```regex
r8_[a-zA-Z0-9_-]{32,}
```

**Example:** `r8_abcdefghijklmnopqrstuvwxyz123456`

## Mistral AI

**Patterns:**
```regex
(?:mistral.*key|mistral[_-]?api)\s*[:=]\s*["\']([\da-z]{32,})
```

## Detection Strategy

The scanner uses:
1. **Direct pattern matching** - Looks for key format directly in code
2. **Environment variable patterns** - Detects `VARIABLE_NAME=key` patterns
3. **Context extraction** - Captures surrounding code for context
4. **Placeholder filtering** - Removes dummy/test values like:
   - All X's: `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`
   - All 0's: `00000000000000000000000000000000`
   - Obvious placeholders: `your_api_key_here`, `xxx`, `yyy`

## Search Queries

The scanner uses multiple search queries to find keys across GitHub:

**Anthropic:**
- `sk-ant-api03-`
- `sk-ant-`
- `ANTHROPIC_API_KEY sk-ant`

**OpenAI:**
- `sk-proj-`
- `openai_api_key sk-`
- `OPENAI_API_KEY sk-`
- `chatgpt api key`

**Google:**
- `AIza gemini`
- `google_api_key AIza`

**Hugging Face:**
- `hf_`
- `hugging_face_token`

**Azure:**
- `azure_openai_key`
- `azure openai api`

**Generic:**
- `api_key export sk-`
- `export API_KEY sk-`

## Common File Types Scanned

- `.env` - Environment configuration
- `.env.txt` - Text-based env files
- `.yml` / `.yaml` - YAML configs
- `.json` - JSON configs
- `.py` - Python files
- `.js` / `.ts` - JavaScript files
- Config files: `config.js`, `settings.py`, `application.properties`
- Markdown files: `.md` (often contains examples/documentation)
- Bash scripts: `.sh`, `.bash`
- Shell history: `.bash_history`, `.zsh_history`

## Validation Methods

### Anthropic/Claude
```python
from anthropic import Anthropic
client = Anthropic(api_key=key)
response = client.messages.create(...)
```

### OpenAI/ChatGPT
```python
from openai import OpenAI
client = OpenAI(api_key=key)
response = client.chat.completions.create(...)
```

### Google Gemini
```python
import google.generativeai as genai
genai.configure(api_key=key)
model = genai.GenerativeModel('gemini-pro')
response = model.generate_content("ping")
```

## Key Length Reference

| API | Min Length | Max Length | Typical |
|-----|-----------|-----------|---------|
| Anthropic | 32 | 108+ | 47-108 |
| OpenAI (sk-) | 20 | 60+ | 48+ |
| OpenAI (sk-proj-) | 35+ | 60+ | 44+ |
| Gemini | 35 | 35 | 35 |
| Hugging Face | 34+ | 50+ | 37 |
| Cohere | 36 | 36 | 36 |
| Replicate | 35+ | 50+ | 37 |

## False Positives to Watch

- Test/example keys in documentation
- Placeholder values in .env.example files
- Keys in comments showing format (often prefixed with "Example:")
- Revoked keys that haven't been removed from repos
- Keys from abandoned projects

The scanner helps filter these with placeholder detection, but manual review is recommended for sensitive findings.
