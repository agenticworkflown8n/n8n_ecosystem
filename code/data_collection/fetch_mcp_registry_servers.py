#!/usr/bin/env python3

import json
import requests
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse

BASE_DIR = Path(__file__).parent.parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "MCP" / "registry"
REGISTRY_SERVERS_FILE = OUTPUT_DIR / "mcp_registry_servers.json"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


class MCPRegistryFetcher:
    
    def __init__(self):
        self.servers = []
    
    def fetch_anthropic_registry(self) -> List[Dict]:
        print("Fetching from Anthropic MCP Registry...")
        servers = []
        
        try:
            base_url = "https://registry.modelcontextprotocol.io/v0.1/servers"
            cursor = None
            page = 1
            max_pages = 1000
            
            while page <= max_pages:
                params = {'limit': 100}
                if cursor:
                    params['cursor'] = cursor
                
                response = requests.get(base_url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    items = data.get('servers', [])
                    
                    for item in items:
                        server_data = item.get('server', {})
                        meta_data = item.get('_meta', {})
                        registry_meta = meta_data.get('io.modelcontextprotocol.registry/official', {})
                        
                        server_name = server_data.get('name', '')
                        description = server_data.get('description', '')
                        repository = server_data.get('repository', {})
                        repo_url = repository.get('url', '') if isinstance(repository, dict) else ''
                        
                        version = server_data.get('version', '')
                        
                        remotes = server_data.get('remotes', [])
                        remote_urls = []
                        if isinstance(remotes, list):
                            for remote in remotes:
                                if isinstance(remote, dict) and 'url' in remote:
                                    remote_urls.append(remote['url'])
                        
                        server_info = {
                            'name': server_name.split('/')[-1] if '/' in server_name else server_name,
                            'full_name': server_name,
                            'description': description,
                            'version': version,
                            'source': 'anthropic_registry',
                            'published_at': registry_meta.get('publishedAt', ''),
                            'updated_at': registry_meta.get('updatedAt', ''),
                            'status': registry_meta.get('status', ''),
                            'is_latest': registry_meta.get('isLatest', False),
                        }
                        
                        if repo_url:
                            server_info['url'] = repo_url
                            server_info['clone_url'] = repo_url + '.git' if 'github.com' in repo_url and not repo_url.endswith('.git') else repo_url
                            server_info['repository'] = repo_url
                        
                        if remote_urls:
                            server_info['remote_urls'] = remote_urls
                        
                        servers.append(server_info)
                    
                    metadata = data.get('metadata', {})
                    next_cursor = metadata.get('nextCursor') or metadata.get('next_cursor') or metadata.get('cursor')
                    
                    if not next_cursor or len(items) == 0:
                        print(f"  No more pages, fetched {len(servers)} total servers")
                        break
                    
                    cursor = next_cursor
                    page += 1
                    
                    if page % 10 == 0:
                        print(f"  Fetched {page-1} pages, total servers so far: {len(servers)}")
                else:
                    print(f"  API returned status {response.status_code}")
                    if response.status_code == 404:
                        print("  Trying GitHub fallback...")
                        return self._fetch_anthropic_github_fallback()
                    break
            
            print(f"  Found {len(servers)} servers from Anthropic registry")
        
        except requests.exceptions.RequestException as e:
            print(f"  Error fetching Anthropic registry: {e}")
            print("  Trying GitHub fallback...")
            return self._fetch_anthropic_github_fallback()
        except Exception as e:
            print(f"  Unexpected error: {e}")
            return self._fetch_anthropic_github_fallback()
        
        return servers
    
    def _fetch_anthropic_github_fallback(self) -> List[Dict]:
        servers = []
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
                            'source': 'anthropic_github_fallback',
                            'stars': repo.get('stargazers_count', 0),
                            'updated_at': repo.get('updated_at', ''),
                        })
                print(f"  Found {len(servers)} servers from GitHub fallback")
        except Exception as e:
            print(f"  Error in GitHub fallback: {e}")
        
        return servers
    
    def fetch_github_topic(self, topic: str = "mcp-server") -> List[Dict]:
        print(f"Fetching from GitHub topic: {topic}...")
        servers = []
        
        try:
            github_api = f"https://api.github.com/search/repositories?q=topic:{topic}&sort=stars&order=desc&per_page=100"
            
            response = requests.get(github_api, timeout=10)
            if response.status_code == 200:
                data = response.json()
                repos = data.get('items', [])
                
                for repo in repos:
                    servers.append({
                        'name': repo['name'],
                        'full_name': repo['full_name'],
                        'description': repo.get('description', ''),
                        'url': repo['html_url'],
                        'clone_url': repo['clone_url'],
                        'source': 'github_topic',
                        'stars': repo.get('stargazers_count', 0),
                        'updated_at': repo.get('updated_at', ''),
                        'topics': repo.get('topics', []),
                    })
            
            print(f"  Found {len(servers)} servers from GitHub topic")
        
        except Exception as e:
            print(f"  Error fetching GitHub topic: {e}")
        
        return servers
    
    def fetch_npm_packages(self) -> List[Dict]:
        print("Fetching from npm...")
        servers = []
        
        try:
            npm_api = "https://registry.npmjs.org/-/v1/search?text=mcp-server&size=100"
            
            response = requests.get(npm_api, timeout=10)
            if response.status_code == 200:
                data = response.json()
                packages = data.get('objects', [])
                
                for pkg in packages:
                    pkg_info = pkg.get('package', {})
                    servers.append({
                        'name': pkg_info.get('name', ''),
                        'description': pkg_info.get('description', ''),
                        'url': pkg_info.get('links', {}).get('npm', ''),
                        'repository': pkg_info.get('links', {}).get('repository', ''),
                        'source': 'npm',
                        'version': pkg_info.get('version', ''),
                        'updated_at': pkg.get('date', {}).get('ts', ''),
                    })
            
            print(f"  Found {len(servers)} packages from npm")
        
        except Exception as e:
            print(f"  Error fetching npm packages: {e}")
        
        return servers
    
    def merge_and_deduplicate(self, all_servers: List[List[Dict]]) -> List[Dict]:
        print("\nMerging and deduplicating servers...")
        
        seen = set()
        merged = []
        
        for server_list in all_servers:
            for server in server_list:
                identifier = server.get('url') or server.get('clone_url') or server.get('full_name') or server.get('name')
                
                if identifier and identifier not in seen:
                    seen.add(identifier)
                    merged.append(server)
        
        print(f"  Total unique servers: {len(merged)}")
        return merged
    
    def save_results(self, servers: List[Dict]):
        result = {
            'generated_at': datetime.now().isoformat(),
            'total_servers': len(servers),
            'servers': servers,
        }
        
        with open(REGISTRY_SERVERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\nResults saved to: {REGISTRY_SERVERS_FILE}")
    
    def generate_summary(self, servers: List[Dict]):
        print("\n" + "=" * 60)
        print("Summary")
        print("=" * 60)
        
        sources = {}
        for server in servers:
            source = server.get('source', 'unknown')
            sources[source] = sources.get(source, 0) + 1
        
        print(f"Total servers: {len(servers)}")
        print("\nBy source:")
        for source, count in sorted(sources.items(), key=lambda x: x[1], reverse=True):
            print(f"  {source}: {count}")
        
        starred = [s for s in servers if s.get('stars', 0) > 0]
        if starred:
            starred.sort(key=lambda x: x.get('stars', 0), reverse=True)
            print("\nTop 10 by stars:")
            for i, server in enumerate(starred[:10], 1):
                print(f"  {i}. {server.get('full_name', server.get('name', 'Unknown'))} ({server.get('stars', 0)} stars)")


def main():
    fetcher = MCPRegistryFetcher()
    
    all_servers = []
    
    anthropic_servers = fetcher.fetch_anthropic_registry()
    all_servers.append(anthropic_servers)
    
    github_servers = fetcher.fetch_github_topic("mcp-server")
    all_servers.append(github_servers)
    
    npm_servers = fetcher.fetch_npm_packages()
    all_servers.append(npm_servers)
    
    merged_servers = fetcher.merge_and_deduplicate(all_servers)
    
    fetcher.save_results(merged_servers)
    
    fetcher.generate_summary(merged_servers)


if __name__ == "__main__":
    main()
