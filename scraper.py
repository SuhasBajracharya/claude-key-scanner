#!/usr/bin/env python3
"""
GitHub Claude API Key Scanner & Validator
Scans public GitHub repositories for exposed Anthropic Claude API keys,
then validates any found keys.
"""

import requests
import time
import re
import json
import argparse
from datetime import datetime
from typing import List, Dict, Optional
import sys
import os
from collections import defaultdict
import base64

try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False
    print("[!] anthropic package not installed. Key validation will be skipped.")
    print("[!] Install with: pip install anthropic")


class GitHubAPIScanner:
    def __init__(self, github_token: Optional[str] = None, validate_keys: bool = False, cache_dir: str = "results", use_cache: bool = True):
        self.base_url = "https://api.github.com"
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Claude-Key-Scanner/2.0"
        }
        
        self.validate_keys = validate_keys and ANTHROPIC_AVAILABLE
        
        if github_token:
            github_token = github_token.strip()
            self.headers["Authorization"] = f"Bearer {github_token}"
            print("[+] Using authenticated requests (higher rate limits)")
            
            if not github_token.startswith(('ghp_', 'github_pat_')):
                print("[!] Warning: Token doesn't match expected format (ghp_ or github_pat_)")
        else:
            print("[!] ERROR: GitHub now REQUIRES authentication for code search")
            print("[!] Please provide a token with --token or set GITHUB_TOKEN environment variable")
            raise ValueError("Authentication token required for GitHub code search")
        
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        self.results = []
        self.stats = defaultdict(int)
        self.token_valid = False
        self.validation_results = {'valid': [], 'invalid': [], 'error': []}
        
        # Cache configuration
        self.use_cache = use_cache
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, ".scan_cache.json")
        self.scanned_repos = {}
        self.cache_ttl_hours = 24  # Cache expires after 24 hours
        
        # Claude API key patterns
        self.claude_key_patterns = [
            r'sk-ant-api\d{2}-[a-zA-Z0-9_-]{32,}',
            r'sk-ant-[a-zA-Z0-9_-]{32,}',
            r'(?:ANTHROPIC_API_KEY|claude.*api[_-]?key)\s*[:=]\s*["\']?(sk-ant-[^"\'\s]+)',
            r'x-api-key["\']?\s*[:=]\s*["\'](sk-ant-[^"\'\s]+)',
            r'apiKey["\']?\s*[:=]\s*["\'](sk-ant-[^"\'\s]+)',
        ]
        
        # Search queries
        self.search_queries = [
            'sk-ant-api03-',
            'sk-ant-',
            'ANTHROPIC_API_KEY sk-ant',
            'anthropic api_key sk-ant',
            'x-api-key sk-ant',
        ]
        
        # Load cache if enabled
        if self.use_cache:
            self.load_cache()

    def check_rate_limits(self) -> bool:
        try:
            response = requests.get(f"{self.base_url}/rate_limit", headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                core_limits = data['resources']['core']
                search_limits = data['resources']['search']
                
                self.rate_limit_remaining = search_limits['remaining']
                reset_timestamp = search_limits['reset']
                self.rate_limit_reset = datetime.fromtimestamp(reset_timestamp)
                
                print(f"[*] Rate limits - Core: {core_limits['remaining']}/{core_limits['limit']}, "
                      f"Search: {search_limits['remaining']}/{search_limits['limit']}")
                
                if search_limits['remaining'] == 0:
                    wait_time = max(0, (self.rate_limit_reset - datetime.now()).total_seconds())
                    if wait_time > 0:
                        print(f"[!] Rate limit exceeded. Reset at {self.rate_limit_reset.strftime('%H:%M:%S')}")
                        print(f"[*] Waiting {wait_time:.0f} seconds...")
                        time.sleep(wait_time + 1)
                        return self.check_rate_limits()
                
                return True
            elif response.status_code == 401:
                print(f"[!] Token validation failed. Please check your GitHub token.")
                return False
            else:
                print(f"[!] Failed to check rate limits: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"[!] Error checking rate limits: {e}")
            return False

    def search_code(self, query: str, max_pages: int = 3) -> List[Dict]:
        results = []
        
        if not self.token_valid:
            print("[*] Testing token validity...")
            test_response = requests.get(f"{self.base_url}/user", headers=self.headers)
            if test_response.status_code == 200:
                user_data = test_response.json()
                print(f"[+] Authenticated as: {user_data.get('login', 'unknown')}")
                self.token_valid = True
            else:
                print(f"[!] Authentication failed: {test_response.status_code}")
                return results
        
        for page in range(1, max_pages + 1):
            if not self.check_rate_limits():
                break
            
            try:
                url = f"{self.base_url}/search/code"
                params = {'q': query, 'per_page': 30, 'page': page}
                
                print(f"[*] Searching page {page}: {query[:50]}...")
                response = requests.get(url, headers=self.headers, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('items', [])
                    
                    if not items:
                        print(f"[*] No more results for query")
                        break
                    
                    results.extend(items)
                    total_count = data.get('total_count', 0)
                    print(f"[+] Found {len(items)} results on page {page} (Total available: {total_count:,})")
                    time.sleep(2)
                    
                elif response.status_code == 403:
                    print(f"[!] Rate limit exceeded or access forbidden")
                    if 'retry-after' in response.headers:
                        wait_time = int(response.headers['retry-after'])
                        print(f"[*] Waiting {wait_time} seconds...")
                        time.sleep(wait_time)
                    else:
                        self.check_rate_limits()
                    continue
                    
                elif response.status_code == 422:
                    print(f"[!] Query too complex or invalid")
                    break
                else:
                    print(f"[!] Error searching: {response.status_code}")
                    break
                    
            except Exception as e:
                print(f"[!] Exception during search: {e}")
                time.sleep(5)
                continue
        
        return results

    def get_file_content(self, repo_full_name: str, file_path: str) -> Optional[str]:
        if not self.check_rate_limits():
            return None
        
        try:
            url = f"{self.base_url}/repos/{repo_full_name}/contents/{file_path}"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                if isinstance(data, list):
                    return None
                    
                if data.get('size', 0) > 1000000:
                    return None
                
                content = base64.b64decode(data['content']).decode('utf-8', errors='ignore')
                return content
                
            elif response.status_code in (403, 404):
                return None
                
        except Exception as e:
            print(f"    [!] Error: {e}")
        
        return None

    def extract_api_keys(self, content: str, repo_name: str, file_path: str) -> List[Dict]:
        findings = []
        
        for pattern in self.claude_key_patterns:
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if match.lastindex and match.lastindex >= 1:
                        api_key = match.group(1)
                    else:
                        api_key = match.group(0)
                    
                    api_key = api_key.strip('"\' \t\n\r')
                    
                    if self._is_likely_valid_key(api_key):
                        start = max(0, match.start() - 40)
                        end = min(len(content), match.end() + 40)
                        context = content[start:end].replace('\n', ' ').strip()
                        
                        # Extract full key from context
                        full_key = self._extract_full_key(context)
                        
                        # Check if placeholder
                        is_placeholder = self._is_placeholder_key(full_key if full_key else api_key)
                        
                        findings.append({
                            'repository': repo_name,
                            'file_path': file_path,
                            'api_key_preview': api_key[:25] + '...' + api_key[-5:],
                            'full_key': full_key,
                            'key_length': len(api_key),
                            'pattern_matched': pattern,
                            'context': context,
                            'is_placeholder': is_placeholder,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        self.stats['keys_found'] += 1
                        
            except Exception as e:
                print(f"    [!] Pattern matching error: {e}")
        
        return findings

    def load_cache(self) -> None:
        """Load scan cache from disk."""
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    self.scanned_repos = json.load(f)
                print(f"[+] Loaded cache with {len(self.scanned_repos)} scanned repos")
            except Exception as e:
                print(f"[!] Failed to load cache: {e}")
                self.scanned_repos = {}
        else:
            self.scanned_repos = {}
    
    def save_cache(self) -> None:
        """Save scan cache to disk."""
        if not self.use_cache:
            return
        
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(self.cache_file, 'w') as f:
                json.dump(self.scanned_repos, f, indent=2)
            print(f"[+] Cache saved ({len(self.scanned_repos)} repos tracked)")
        except Exception as e:
            print(f"[!] Failed to save cache: {e}")
    
    def is_repo_cached(self, repo_name: str) -> bool:
        """Check if a repo has already been scanned (and cache hasn't expired)."""
        if not self.use_cache:
            return False
        
        if repo_name not in self.scanned_repos:
            return False
        
        # Check if cache entry has expired
        cached_entry = self.scanned_repos[repo_name]
        if isinstance(cached_entry, dict) and 'timestamp' in cached_entry:
            try:
                cached_time = datetime.fromisoformat(cached_entry['timestamp'])
                age_hours = (datetime.now() - cached_time).total_seconds() / 3600
                
                if age_hours > self.cache_ttl_hours:
                    # Cache expired, mark for re-scan
                    return False
            except Exception:
                pass
        
        return True
    
    def mark_repo_scanned(self, repo_name: str, findings_count: int = 0) -> None:
        """Mark a repo as scanned in the cache."""
        if not self.use_cache:
            return
        
        self.scanned_repos[repo_name] = {
            'timestamp': datetime.now().isoformat(),
            'findings': findings_count
        }

    def _extract_full_key(self, context: str) -> Optional[str]:
        """Extract the full API key from context."""
        patterns = [
            r'sk-ant-api\d{2}-[a-zA-Z0-9_-]{30,}',
            r'sk-ant-[a-zA-Z0-9_-]{30,}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, context)
            if match:
                full_key = match.group(0)
                full_key = full_key.rstrip('"\'.,;:} \t\n\r')
                return full_key
        
        return None

    def _is_likely_valid_key(self, key: str) -> bool:
        if not key:
            return False
        
        if re.match(r'^sk-ant-api\d{2}-[a-zA-Z0-9_-]{32,}$', key):
            return True
        if re.match(r'^sk-ant-[a-zA-Z0-9_-]{32,}$', key):
            return True
            
        return False

    def _is_placeholder_key(self, key: str) -> bool:
        """Check if a key is just a placeholder (all X's or all 0's)."""
        if not key:
            return True
        
        # Remove prefix to check the actual key part
        key_part = key
        for prefix in ['sk-ant-api03-', 'sk-ant-api02-', 'sk-ant-api01-', 'sk-ant-']:
            if key_part.startswith(prefix):
                key_part = key_part[len(prefix):]
                break
        
        # Remove common suffixes that might be artifacts
        key_part = key_part.rstrip('"\'.,;:} \t\n\r')
        
        # Check if all alpha characters are 'x' or 'X'
        alpha_chars = [c for c in key_part if c.isalpha()]
        if alpha_chars and all(c.lower() == 'x' for c in alpha_chars):
            return True
        
        # Check if all chars are '0' or '-'
        if all(c in '0-' for c in key_part):
            return True
        
        return False

    def validate_api_key(self, api_key: str) -> tuple:
        """Validate a single API key using Anthropic's API."""
        if not ANTHROPIC_AVAILABLE:
            return False, "Anthropic package not installed"
        
        try:
            client = Anthropic(api_key=api_key)
            response = client.messages.create(
                model="claude-3-haiku-20240307",
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}]
            )
            return True, f"Response: {response.content[0].text}"
        except Exception as e:
            return False, str(e)[:200]

    def scan(self, max_queries: Optional[int] = None, max_pages_per_query: int = 3):
        print("[*] Starting GitHub scan for exposed Claude API keys")
        
        if self.validate_keys:
            print("[*] Key validation ENABLED - will test found keys")
        else:
            print("[*] Key validation DISABLED")
        
        queries_to_use = self.search_queries
        if max_queries:
            queries_to_use = queries_to_use[:max_queries]
            
        print(f"[*] Using {len(queries_to_use)} search queries")
        print(f"[*] Fetching up to {max_pages_per_query} pages per query")
        print("-" * 60)
        
        # Track unique keys for validation (key -> set of repos)
        unique_keys = {}
        
        for i, query in enumerate(queries_to_use, 1):
            print(f"\n[{i}/{len(queries_to_use)}] Processing query: '{query}'")
            
            search_results = self.search_code(query, max_pages=max_pages_per_query)
            self.stats['total_search_results'] += len(search_results)
            
            if not search_results:
                print(f"[*] No results found for this query")
                continue
            
            for j, result in enumerate(search_results, 1):
                repo_name = result['repository']['full_name']
                file_path = result['path']
                
                # Check if repo already scanned
                if self.is_repo_cached(repo_name):
                    print(f"  [{j}/{len(search_results)}] {repo_name} (cached, skipping)")
                    self.stats['repos_cached'] += 1
                    continue
                
                print(f"  [{j}/{len(search_results)}] Checking {repo_name}/{file_path}")
                
                if self._should_skip_file(file_path):
                    print(f"    [-] Skipping (excluded file type)")
                    continue
                
                content = self.get_file_content(repo_name, file_path)
                
                if content:
                    findings = self.extract_api_keys(content, repo_name, file_path)
                    
                    if findings:
                        for finding in findings:
                            full_key = finding.get('full_key')
                            is_placeholder = finding.get('is_placeholder', True)
                            
                            # Store unique non-placeholder keys for validation
                            if full_key and not is_placeholder:
                                if full_key not in unique_keys:
                                    unique_keys[full_key] = set()
                                unique_keys[full_key].add(repo_name)
                            
                            status = "[PLACEHOLDER]" if is_placeholder else "[REAL]"
                            print(f"    [!] FOUND {status} potential API key!")
                            print(f"        Key preview: {finding['api_key_preview']}")
                            print(f"        Context: {finding['context'][:80]}...")
                        
                        self.results.extend(findings)
                        if any(not f.get('is_placeholder', True) for f in findings):
                            self.stats['affected_repos'] += 1
                        
                        # Mark repo as scanned with findings count
                        self.mark_repo_scanned(repo_name, len(findings))
                    else:
                        # Mark repo as scanned even with no findings
                        self.mark_repo_scanned(repo_name, 0)
                
                self.stats['files_checked'] += 1
                
                if j % 5 == 0:
                    time.sleep(2)
            
            if i < len(queries_to_use):
                print(f"[*] Waiting 5 seconds before next query...")
                time.sleep(5)
        
        # Show unique keys found
        if unique_keys:
            print(f"\n[*] Found {len(unique_keys)} unique non-placeholder keys to validate")
        
        # Validate found keys
        if self.validate_keys and unique_keys:
            print("\n" + "=" * 60)
            print("[*] Validating found API keys...")
            print(f"[*] Testing {len(unique_keys)} unique keys")
            print("=" * 60)
            
            for idx, (api_key, repos) in enumerate(unique_keys.items(), 1):
                print(f"\n[{idx}/{len(unique_keys)}] Testing key: {api_key[:25]}...{api_key[-5:]}")
                print(f"    Full length: {len(api_key)} chars")
                print(f"    Found in: {', '.join(sorted(repos))}")
                print(f"    Testing...")
                
                is_valid, message = self.validate_api_key(api_key)
                
                if is_valid:
                    print(f"    [+] VALID KEY ✓")
                    self.validation_results['valid'].append({
                        'key_preview': f"{api_key[:25]}...{api_key[-5:]}",
                        'repositories': list(repos),
                        'response': message
                    })
                elif any(x in message.lower() for x in ['401', 'unauthorized', 'authentication', 'invalid', 'permission']):
                    print(f"    [-] INVALID/REVOKED KEY ✗")
                    self.validation_results['invalid'].append({
                        'key_preview': f"{api_key[:25]}...{api_key[-5:]}",
                        'repositories': list(repos),
                        'error': message
                    })
                else:
                    print(f"    [!] ERROR (not auth-related)")
                    self.validation_results['error'].append({
                        'key_preview': f"{api_key[:25]}...{api_key[-5:]}",
                        'repositories': list(repos),
                        'error': message
                    })
                
                print(f"    {message[:150]}")
        
        print("\n" + "=" * 60)
        print(self.get_summary())
        
        # Save cache after scan completes
        self.save_cache()
        
        return self.results

    def _should_skip_file(self, file_path: str) -> bool:
        skip_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.zip', '.tar', '.gz', '.rar', '.7z',
            '.exe', '.dll', '.so', '.dylib',
            '.mp3', '.mp4', '.avi', '.mov', '.wmv',
            '.ttf', '.otf', '.woff', '.woff2',
            '.min.js', '.min.css', '.map'
        }
        
        file_lower = file_path.lower()
        file_ext = os.path.splitext(file_lower)[1]
        
        if file_ext in skip_extensions:
            return True
        
        if file_lower.endswith(('.lock', '.pyc', '.class', '.jar')):
            return True
            
        return False

    def get_summary(self) -> str:
        summary = []
        summary.append("=" * 60)
        summary.append("SCAN SUMMARY")
        summary.append("=" * 60)
        summary.append(f"Total search results examined: {self.stats['total_search_results']}")
        summary.append(f"Files checked: {self.stats['files_checked']}")
        summary.append(f"Repositories cached (skipped): {self.stats.get('repos_cached', 0)}")
        summary.append(f"Potential API keys found: {self.stats['keys_found']}")
        summary.append(f"Affected repositories: {self.stats['affected_repos']}")
        
        if self.validate_keys:
            summary.append(f"\nValidation Results:")
            summary.append(f"  ✓ Valid keys: {len(self.validation_results['valid'])}")
            summary.append(f"  ✗ Invalid keys: {len(self.validation_results['invalid'])}")
            summary.append(f"  ! Errors: {len(self.validation_results['error'])}")
            
            if self.validation_results['valid']:
                summary.append(f"\n[!] ⚠️  VALID API KEYS FOUND:")
                for key_data in self.validation_results['valid']:
                    for repo in key_data['repositories']:
                        summary.append(f"    • {repo}")
                    summary.append(f"      Key: {key_data['key_preview']}")
        
        if self.results:
            # Show only non-placeholder findings
            real_findings = [f for f in self.results if not f.get('is_placeholder', False)]
            if real_findings:
                summary.append(f"\nTop real findings:")
                for i, finding in enumerate(real_findings[:5], 1):
                    summary.append(f"{i}. {finding['repository']}")
                    summary.append(f"   File: {finding['file_path']}")
                    summary.append(f"   Key: {finding['api_key_preview']}")
                    summary.append(f"   Context: {finding['context'][:100]}...")
        else:
            summary.append("\nNo exposed Claude API keys found.")
            
        return "\n".join(summary)

    def save_results(self, output_dir: str = "results"):
        """Save findings to a timestamped JSON file in the results directory."""
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = os.path.join(output_dir, f"{timestamp}.json")

        output = {
            'scan_date': datetime.now().isoformat(),
            'summary': {
                'total_search_results': self.stats['total_search_results'],
                'files_checked': self.stats['files_checked'],
                'keys_found': self.stats['keys_found'],
                'affected_repos': self.stats['affected_repos']
            },
            'validation_results': self.validation_results,
            'findings': self.results
        }
        
        with open(filename, 'w') as f:
            json.dump(output, f, indent=2)
        print(f"[+] Results saved to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Scan GitHub for exposed Claude API keys and optionally validate them',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan only
  python scanner.py --token ghp_xxx
  
  # Scan and validate found keys
  python scanner.py --token ghp_xxx --validate
  
  # Limited scan with validation
  python scanner.py --token ghp_xxx --max-queries 3 --max-pages 2 --validate
  
    # Custom output directory
    python scanner.py --token ghp_xxx --validate --output results

NOTE: GitHub REQUIRES authentication for code search.
Get a token from: https://github.com/settings/tokens
The token needs 'public_repo' scope.
        """
    )
    
    parser.add_argument('--token', '-t', help='GitHub personal access token (REQUIRED)')
    parser.add_argument('--validate', '-v', action='store_true',
                       help='Validate found API keys against Claude API')
    parser.add_argument('--max-queries', type=int, default=None,
                       help='Maximum number of search queries (default: all)')
    parser.add_argument('--max-pages', type=int, default=3,
                       help='Maximum pages per query (default: 3)')
    parser.add_argument('--output', '-o', default='results',
                       help='Output directory for results (default: results)')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable repo caching (always scan all repos)')
    parser.add_argument('--force-refresh', action='store_true',
                       help='Clear cache before scanning')
    
    args = parser.parse_args()
    
    token = args.token or os.environ.get('GITHUB_TOKEN')
    
    if not token:
        print("[!] ERROR: GitHub token is REQUIRED for code search!")
        print("[!] Get a token from: https://github.com/settings/tokens")
        print("[!] Select 'public_repo' scope when creating the token")
        sys.exit(1)
    
    if args.validate and not ANTHROPIC_AVAILABLE:
        print("[!] Cannot validate keys: anthropic package not installed")
        print("[!] Install with: pip install anthropic")
        print("[!] Continuing with scan only...")
        args.validate = False
    
    try:
        # Handle cache refresh flag
        if args.force_refresh:
            cache_file = os.path.join(args.output, ".scan_cache.json")
            if os.path.exists(cache_file):
                os.remove(cache_file)
                print("[+] Cache cleared")
        
        scanner = GitHubAPIScanner(
            token, 
            validate_keys=args.validate,
            cache_dir=args.output,
            use_cache=not args.no_cache
        )
        scanner.scan(
            max_queries=args.max_queries,
            max_pages_per_query=args.max_pages
        )
        
        scanner.save_results(args.output)
        
        if args.validate and scanner.validation_results['valid']:
            print(f"\n[!] ⚠️  WARNING: Found {len(scanner.validation_results['valid'])} VALID API keys!")
            print("[!] Consider responsibly disclosing to repository owners:")
            print("[!] https://github.com/<owner>/<repo>/security/advisories/new")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        if 'scanner' in locals() and scanner.results:
            scanner.save_results(args.output)
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()