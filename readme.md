# AI API Key Scanner

A security tool to scan public GitHub repositories for exposed AI API keys (Claude, OpenAI, Gemini, and more) and optionally validate them.

## Features

- Searches GitHub public repositories for exposed AI API keys from multiple providers
- Validates found keys against their respective APIs
- Auto-detects API type for each detected key  
- Filters out placeholder keys (test/dummy values)
- Saves detailed results to timestamped JSON reports in the `results/` folder
- Repository-based caching to avoid redundant scans
- Rate limit aware with automatic retry logic

## Supported API Services

- ✅ Anthropic/Claude (`sk-ant-*`)
- ✅ OpenAI/ChatGPT (`sk-*` / `sk-proj-*`)
- ✅ Google Gemini/Vertex AI (`AIza*`)
- ✅ Hugging Face (`hf_*`)
- ✅ Cohere
- ✅ DeepSeek  
- ✅ Azure OpenAI
- ✅ Replicate (`r8_*`)
- ✅ Mistral AI

## Prerequisites

- Python 3.7+
- GitHub Personal Access Token ([create here](https://github.com/settings/tokens))
  - Requires `public_repo` scope for code search

## Installation

### Required
```bash
pip install requests
```

### Optional (for key validation)
```bash
# For Claude validation
pip install anthropic

# For OpenAI validation
pip install openai

# For Gemini validation
pip install google-generativeai

# Install all validators
pip install anthropic openai google-generativeai
```

## Files

- `scraper.py` - Main scanner that searches GitHub and validates keys
- `validator.py` - Claude key validator utility
- `openai_test.py` - OpenAI key validator utility
- `results/` - Output directory for timestamped scan results

## Usage

### Basic Scan (No Validation)
```bash
python scraper.py --token YOUR_TOKEN
```

### Scan with Key Validation
```bash
python scraper.py --token YOUR_TOKEN --validate
```

### Limited Scan with Validation
```bash
python scraper.py --token YOUR_TOKEN --max-queries 3 --max-pages 2 --validate
```

### Clear Cache and Re-scan
```bash
python scraper.py --token YOUR_TOKEN --force-refresh --validate
```

### Using Environment Variable
```bash
export GITHUB_TOKEN="your_token"
python scraper.py --validate
```

## Caching

By default, the scanner maintains a cache of already-scanned repositories to improve performance on subsequent scans.

### Disable Caching
```bash
python scraper.py --token YOUR_TOKEN --no-cache
```

### Clear Cache and Force Full Rescan
```bash
python scraper.py --token YOUR_TOKEN --force-refresh
```

The cache is stored as `.scan_cache.json` in the results directory and tracks:
- Repository name
- Last scan timestamp  
- Number of findings per repo
- Cache entries expire after 24 hours

## Results

Scan results are saved to the `results/` directory as timestamped JSON files with the format: `YYYY-MM-DD_HH-MM-SS.json`

Each result file contains:
- Scan metadata and timestamps
- Summary statistics (breakdown by API type)
- Detailed findings with:
  - Repository information
  - API type and name
  - Key preview and full key (if applicable)
  - Pattern matched
  - Context where key was found
  - Placeholder detection
- Validation results for found keys:
  - Valid keys (working)
  - Invalid/Revoked keys
  - Validation errors

## Limitations

- GitHub rate limits: 30 requests per minute for authenticated users
- Placeholder detection helps avoid false positives but isn't 100% accurate
- Validation requires having valid API keys for testing
- Some API types may have similar key formats (e.g., DeepSeek vs OpenAI)

## Ethical Considerations

This tool is designed for security research and ethical penetration testing. When valid keys are found:

1. **Do not use** the keys without authorization
2. **Report responsibly** to the repository owner
3. Use GitHub's security advisory feature: `https://github.com/<owner>/<repo>/security/advisories/new`
4. Consider notifying the API provider
5. Verify the key hasn't already been revoked

## Recent Updates

See [UPDATES.md](UPDATES.md) for details on recent enhancements including multi-API support.