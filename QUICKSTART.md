# Installation & Quick Start Guide

## Quick Setup

### 1. Install Dependencies

```bash
# Core requirements
pip install requests

# Optional: Install validation packages (choose which ones you need)
pip install anthropic          # For Claude validation
pip install openai             # For OpenAI validation  
pip install google-generativeai # For Gemini validation

# Install all at once
pip install anthropic openai google-generativeai
```

### 2. Get GitHub Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token"
3. Select scope: `public_repo`
4. Copy the token

### 3. Run Scanner

```bash
# Basic scan (no validation)
python scraper.py --token ghp_your_token_here

# Or use environment variable
export GITHUB_TOKEN="ghp_your_token_here"
python scraper.py

# With validation enabled
python scraper.py --validate

# Clear cache and rescan everything
python scraper.py --force-refresh --validate

# Limited scan (first 5 queries, 2 pages each)
python scraper.py --max-queries 5 --max-pages 2 --validate
```

## What Gets Scanned

The script automatically searches for:

- **Claude/Anthropic** API keys (sk-ant-*)
- **OpenAI/ChatGPT** API keys (sk-*, sk-proj-*)
- **Google Gemini** API keys (AIza*)
- **Hugging Face** tokens (hf_*)
- **Cohere** API keys
- **DeepSeek** tokens
- **Azure OpenAI** keys
- **Replicate** tokens (r8_*)
- **Mistral AI** keys
- Plus more...

## Understanding Results

Results are saved in `results/YYYY-MM-DD_HH-MM-SS.json`

Example finding:
```json
{
  "repository": "user/exposed-secrets",
  "file_path": ".env.backup",
  "api_type": "openai",
  "api_name": "OpenAI/ChatGPT",
  "api_key_preview": "sk-proj-abc123...xyz789",
  "full_key": "sk-proj-...",
  "key_length": 48,
  "is_placeholder": false,
  "context": "API_KEY=sk-proj-abc123...xyz789-test"
}
```

## Validation Results

When using `--validate`, each valid key found will show:

- ✓ **VALID** - Key is working and accessible
- ✗ **INVALID** - Key is expired or revoked  
- ! **ERROR** - Network/testing issue

## Caching

The script caches scanned repositories to avoid redundant work:

- Cache location: `results/.scan_cache.json`
- Cache expires: After 24 hours
- Clear cache: Use `--force-refresh` flag
- Disable cache: Use `--no-cache` flag

## Troubleshooting

### "GitHub token is REQUIRED"
```bash
# Provide token via flag
python scraper.py --token ghp_xxx

# Or set environment variable
export GITHUB_TOKEN="ghp_xxx"
python scraper.py
```

### "Cannot validate keys: anthropic package not installed"
```bash
# Install missing package
pip install anthropic openai google-generativeai
```

### Rate limit exceeded
- The script automatically waits and retries
- Can also use `--max-queries` to limit search scope

### Too many cached repos (old cache)
```bash
# Clear old cache and rescan
python scraper.py --force-refresh
```

## Advanced Usage

### Custom output directory
```bash
python scraper.py --token ghp_xxx --output my_results --validate
```

### One API type at a time (manual multi-run)
The scanner searches all APIs by default. To focus on specific ones, create your own search script or edit `self.search_queries` in scraper.py

### Monitoring long scans
The script shows progress:
- Current query and page
- Repository being scanned
- Keys found with type and preview
- Real-time validation results

## Performance Tips

1. **Use caching** (default): Skips already-scanned repos
2. **Limit queries**: `--max-queries 5` for quick scans
3. **Limit pages**: `--max-pages 2` for faster results
4. **Run overnight**: Use nohup or screen for long scans

```bash
# Run in background, save output to log
nohup python scraper.py --token ghp_xxx --validate > scan.log 2>&1 &

# Monitor progress
tail -f scan.log
```

## Example: Full Security Scan

```bash
#!/bin/bash

export GITHUB_TOKEN="ghp_your_token"

# Clear old results and cache
rm -rf results
mkdir results

# Run full scan with all validation
python scraper.py \
  --token $GITHUB_TOKEN \
  --validate \
  --output results \
  --force-refresh

# Results saved to results/YYYY-MM-DD_HH-MM-SS.json
echo "Scan complete! Check results directory."
```

## Files Generated

After running the scanner:

```
results/
├── .scan_cache.json              # Repository scan cache
├── 2026-05-01_12-34-56.json      # Scan results (latest)
└── 2026-04-30_22-10-50.json      # Previous scan results
```

Each JSON file contains complete findings with context and validation status.

## Next Steps

1. Review the results JSON files
2. Check for real (non-placeholder) keys
3. If valid keys found:
   - Verify not in .env.example or documentation
   - Check if key has been revoked
   - Prepare responsible disclosure
4. Report findings to repo owners
5. Monitor for patterns in which APIs are most exposed

## Additional Resources

- See [UPDATES.md](UPDATES.md) for recent changes
- See [API_PATTERNS.md](API_PATTERNS.md) for technical pattern details
- GitHub token creation: https://github.com/settings/tokens
- Responsible disclosure: https://docs.github.com/en/code-security/security-advisories
