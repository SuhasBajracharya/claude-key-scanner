# Claude Key Scanner

A security tool to scan public GitHub repositories for exposed Anthropic Claude API keys and optionally validate their authenticity.

## Features

- Searches GitHub public repositories for exposed Claude API keys
- Validates found keys against the Claude API
- Filters out placeholder keys (test/dummy values)
- Saves detailed results to timestamped JSON reports in the `results/` folder
- Supports environment variable authentication
- Rate limit aware with automatic retry logic

## Prerequisites

- Python 3.7+
- GitHub Personal Access Token ([create here](https://github.com/settings/tokens))
  - Requires `public_repo` scope for code search
- Anthropic API credentials (optional, only needed for key validation)

## Installation

```bash
pip install requests anthropic
```

## Files

- `scraper.py` - Main scanner that searches GitHub and validates keys
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

### Custom Output Directory
```bash
python scraper.py --token YOUR_TOKEN --validate --output results
```

### Using Environment Variable
```bash
export GITHUB_TOKEN="your_token"
python scraper.py --validate
```

## Results

Scan results are saved to the `results/` directory as timestamped JSON files with the format: `YYYY-MM-DD_HH-MM-SS.json`

Each result file contains:
- Scan metadata and timestamps
- Summary statistics
- Detailed findings with context
- Validation results (if applicable)