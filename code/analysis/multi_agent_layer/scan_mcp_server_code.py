#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import shutil
import requests
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, List, Optional, Set
import hashlib

BASE_DIR = Path(__file__).parent.parent.parent
REGISTRY_DIR = BASE_DIR / "data" / "MCP" / "registry"
REGISTRY_SERVERS_FILE = REGISTRY_DIR / "mcp_registry_servers.json"

OUTPUT_DIR = BASE_DIR / "data" / "MCP" / "code_analysis"
CODE_CACHE_DIR = OUTPUT_DIR / "code_cache"
RESULTS_FILE = OUTPUT_DIR / "mcp_code_scan_results.json"
REPORT_FILE = OUTPUT_DIR / "mcp_code_scan_report.md"

REGISTRY_DIR.mkdir(parents=True, exist_ok=True)


class MCPServerCodeScanner:
    def __init__(self):
        self.scan_results = defaultdict(dict)
        self.risk_patterns = self._load_risk_patterns()

    def _load_risk_patterns(self) -> Dict[str, List[re.Pattern]]:
        return {
            'command_injection': [
                re.compile(r'exec\s*\(', re.IGNORECASE),
                re.compile(r'eval\s*\(', re.IGNORECASE),
                re.compile(r'spawn\s*\(', re.IGNORECASE),
                re.compile(r'execSync\s*\(', re.IGNORECASE),
                re.compile(r'shell\s*=\s*true', re.IGNORECASE),
                re.compile(r'child_process', re.IGNORECASE),
            ],
            'file_system_access': [
                re.compile(r'fs\.(read|write|unlink|rmdir|mkdir)', re.IGNORECASE),
                re.compile(r'readFile|writeFile|unlink|rmdir|mkdir', re.IGNORECASE),
                re.compile(r'path\.join.*process\.env', re.IGNORECASE),
                re.compile(r'\.\.\/', re.IGNORECASE),
            ],
            'network_access': [
                re.compile(r'fetch\s*\(', re.IGNORECASE),
                re.compile(r'axios\s*\(', re.IGNORECASE),
                re.compile(r'http\.(get|post|request)', re.IGNORECASE),
                re.compile(r'https\.(get|post|request)', re.IGNORECASE),
                re.compile(r'request\s*\(', re.IGNORECASE),
            ],
            'sensitive_data': [
                re.compile(r'password\s*[:=]', re.IGNORECASE),
                re.compile(r'api[_-]?key\s*[:=]', re.IGNORECASE),
                re.compile(r'secret\s*[:=]', re.IGNORECASE),
                re.compile(r'token\s*[:=]', re.IGNORECASE),
                re.compile(r'process\.env\.[A-Z_]+', re.IGNORECASE),
            ],
            'input_validation': [
                re.compile(r'JSON\.parse\s*\(', re.IGNORECASE),
                re.compile(r'eval\s*\(', re.IGNORECASE),
                re.compile(r'new Function\s*\(', re.IGNORECASE),
            ],
            'permission_scope': [
                re.compile(r'allow.*all', re.IGNORECASE),
                re.compile(r'permission.*\*', re.IGNORECASE),
                re.compile(r'read.*write.*execute', re.IGNORECASE),
            ],
        }
    
    def fetch_anthropic_registry_servers(self) -> List[Dict]:
        print("Fetching MCP servers from Anthropic Registry...")
        servers = []
        if REGISTRY_SERVERS_FILE.exists():
            try:
                with open(REGISTRY_SERVERS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    servers = data.get('servers', [])
                    print(f"  Loaded {len(servers)} servers from cached registry data")
                    return servers
            except Exception as e:
                print(f"  Error reading cached registry: {e}")
        try:
            github_org = "modelcontextprotocol"
            github_api = f"https://api.github.com/orgs/{github_org}/repos"
            
            response = requests.get(github_api, timeout=10)
            if response.status_code == 200:
                repos = response.json()
                for repo in repos:
                    if 'mcp' in repo['name'].lower() or 'server' in repo['name'].lower():
                        servers.append({
                            'name': repo['name'],
                            'full_name': repo['full_name'],
                            'description': repo.get('description', ''),
                            'url': repo['html_url'],
                            'clone_url': repo['clone_url'],
                            'source': 'anthropic_github',
                            'stars': repo.get('stargazers_count', 0),
                            'updated_at': repo.get('updated_at', ''),
                        })
                
                print(f"  Found {len(servers)} servers from Anthropic GitHub org")
        
        except Exception as e:
            print(f"  Error fetching from Anthropic registry: {e}")
        
        return servers
    
    def get_repository_url(self, server: Dict) -> Optional[str]:
        if 'clone_url' in server and server['clone_url']:
            return server['clone_url']
        if 'url' in server and server['url']:
            url = server['url']
            if 'github.com' in url:
                if not url.endswith('.git'):
                    return url + '.git'
                return url
        if 'repository' in server and server['repository']:
            repo = server['repository']
            if isinstance(repo, str):
                if 'github.com' in repo:
                    if not repo.endswith('.git'):
                        return repo + '.git'
                    return repo
            elif isinstance(repo, dict):
                if 'url' in repo:
                    return repo['url']
        
        return None
    
    def clone_or_download_code(self, repo_url: str, server_name: str) -> Optional[Path]:
        cache_key = hashlib.md5(f"{repo_url}{server_name}".encode()).hexdigest()
        cache_path = CODE_CACHE_DIR / cache_key
        
        if cache_path.exists():
            print(f"  Using cached code: {cache_path}")
            return cache_path
        if 'github.com' in repo_url:
            try:
                print(f"  Cloning {repo_url}...")
                result = subprocess.run(
                    ['git', 'clone', '--depth', '1', repo_url, str(cache_path)],
                    check=True,
                    capture_output=True,
                    timeout=60,
                    text=True
                )
                if cache_path.exists():
                    return cache_path
            except subprocess.TimeoutExpired:
                print(f"  Timeout cloning {repo_url}")
            except subprocess.CalledProcessError as e:
                print(f"  Failed to clone {repo_url}: {e.stderr if hasattr(e, 'stderr') else str(e)}")
            except Exception as e:
                print(f"  Error cloning {repo_url}: {e}")
        
        return None
    
    def scan_code_directory(self, code_path: Path, server_name: str) -> Dict:
        results = {
            'server': server_name,
            'code_path': str(code_path),
            'risks': defaultdict(list),
            'files_scanned': 0,
            'total_issues': 0,
        }
        
        if not code_path.exists():
            return results
        code_extensions = {'.js', '.ts', '.py', '.go', '.rs', '.java', '.cpp', '.c'}
        
        for file_path in code_path.rglob('*'):
            if file_path.is_file() and file_path.suffix in code_extensions:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    results['files_scanned'] += 1
                    relative_path = file_path.relative_to(code_path)
                    for risk_type, patterns in self.risk_patterns.items():
                        for pattern in patterns:
                            matches = pattern.finditer(content)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                results['risks'][risk_type].append({
                                    'file': str(relative_path),
                                    'line': line_num,
                                    'match': match.group(),
                                    'context': self._get_context(content, match.start(), match.end()),
                                })
                                results['total_issues'] += 1
                
                except Exception as e:
                    print(f"    Error scanning {file_path}: {e}")
                    continue
        
        return results
    
    def _get_context(self, content: str, start: int, end: int, context_lines: int = 2) -> str:
        lines = content.split('\n')
        start_line = content[:start].count('\n')
        end_line = content[:end].count('\n')
        
        context_start = max(0, start_line - context_lines)
        context_end = min(len(lines), end_line + context_lines + 1)
        
        context = '\n'.join(lines[context_start:context_end])
        return context
    
    def analyze_dependencies(self, code_path: Path) -> Dict:
        dependencies = {
            'package.json': None,
            'requirements.txt': None,
            'go.mod': None,
            'Cargo.toml': None,
            'pom.xml': None,
        }
        for dep_file in dependencies.keys():
            dep_path = code_path / dep_file
            if dep_path.exists():
                try:
                    with open(dep_path, 'r', encoding='utf-8') as f:
                        dependencies[dep_file] = f.read()
                except Exception as e:
                    print(f"    Error reading {dep_file}: {e}")
        
        return dependencies
    
    def generate_report(self):
        print("\nGenerating report...")
        with open(RESULTS_FILE, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            f.write("# MCP Server Code Security Scan Report\n\n")
            f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("---\n\n")
            
            f.write("## Summary\n\n")
            total_servers = len(self.scan_results)
            total_issues = sum(r.get('total_issues', 0) for r in self.scan_results.values())
            f.write(f"- **Total servers scanned:** {total_servers}\n")
            f.write(f"- **Total security issues found:** {total_issues}\n\n")
            
            f.write("## Detailed Results\n\n")
            
            for server_name, results in self.scan_results.items():
                server_info = results.get('server_info', {})
                f.write(f"### {server_name}\n\n")
                if server_info.get('description'):
                    f.write(f"- **Description:** {server_info['description']}\n")
                if server_info.get('url'):
                    f.write(f"- **Repository:** {server_info['url']}\n")
                if server_info.get('stars', 0) > 0:
                    f.write(f"- **Stars:** {server_info['stars']}\n")
                f.write(f"- **Code path:** `{results.get('code_path', 'N/A')}`\n")
                f.write(f"- **Files scanned:** {results.get('files_scanned', 0)}\n")
                f.write(f"- **Total issues:** {results.get('total_issues', 0)}\n\n")
                
                if results.get('risks'):
                    f.write("#### Security Risks\n\n")
                    for risk_type, issues in results['risks'].items():
                        if issues:
                            f.write(f"**{risk_type.replace('_', ' ').title()}:** {len(issues)} issues\n\n")
                            for issue in issues[:5]:
                                f.write(f"- `{issue['file']}:{issue['line']}` - {issue['match']}\n")
                            if len(issues) > 5:
                                f.write(f"- ... and {len(issues) - 5} more issues\n")
                            f.write("\n")
                
                f.write("---\n\n")
        
        print(f"Report saved to: {REPORT_FILE}")


def main():
    print("=" * 60)
    print("MCP Server Code Security Scanner")
    print("=" * 60)
    
    scanner = MCPServerCodeScanner()
    servers = scanner.fetch_anthropic_registry_servers()
    
    if not servers:
        print("No MCP servers found in registry.")
        print("You may need to run fetch_mcp_registry_servers.py first.")
        return
    
    print(f"\nFound {len(servers)} MCP servers from Anthropic Registry")
    max_servers = 50
    scanned_count = 0
    
    for server in servers[:max_servers]:
        server_name = server.get('full_name') or server.get('name', 'Unknown')
        print(f"\nProcessing server: {server_name}")
        repo_url = scanner.get_repository_url(server)
        
        if not repo_url:
            print(f"  Could not identify repository URL")
            continue
        code_path = scanner.clone_or_download_code(repo_url, server_name)
        
        if not code_path:
            print(f"  Could not download code")
            continue
        print(f"  Scanning code...")
        scan_results = scanner.scan_code_directory(code_path, server_name)
        dependencies = scanner.analyze_dependencies(code_path)
        scan_results['dependencies'] = dependencies
        scan_results['server_info'] = {
            'name': server.get('name'),
            'full_name': server.get('full_name'),
            'description': server.get('description'),
            'url': server.get('url'),
            'source': server.get('source'),
            'stars': server.get('stars', 0),
        }
        
        scanner.scan_results[server_name] = scan_results
        scanned_count += 1
        
        if scanned_count % 10 == 0:
            print(f"\n  Progress: {scanned_count}/{min(len(servers), max_servers)} servers scanned")

    scanner.generate_report()
    
    print("\n" + "=" * 60)
    print("Scan completed!")
    print(f"Scanned {scanned_count} servers")
    print(f"Results saved to: {RESULTS_FILE}")
    print(f"Report saved to: {REPORT_FILE}")
    print("=" * 60)


if __name__ == "__main__":
    main()
