#!/usr/bin/env python3
"""
Find high-risk templates that are both multi-agent (2+ agent nodes) and use community MCP nodes (non-official).
"""

import json
from pathlib import Path
from collections import defaultdict


AGENT_NODE_TYPE = '@n8n/n8n-nodes-langchain.agent'


OFFICIAL_MCP_NODE_TYPES = [
    '@n8n/n8n-nodes-langchain.mcpTrigger',
    '@n8n/n8n-nodes-langchain.mcpClient',
    '@n8n/n8n-nodes-langchain.mcpServer',
]


MCP_KEYWORDS = ['mcp', 'model context protocol']

def is_agent_node(node):
    node_type = node.get('type', '')
    return node_type == AGENT_NODE_TYPE

def is_community_mcp_node(node):
    node_type = node.get('type', '').lower()
    node_name = node.get('name', '').lower()
    

    for official_type in OFFICIAL_MCP_NODE_TYPES:
        if official_type.lower() in node_type:
            return False
    

    if 'mcp' in node_type or 'mcp' in node_name:
        return True
    

    if any(keyword in node_name for keyword in MCP_KEYWORDS):
        return True
    
    return False

def extract_nodes_from_template(template):
    workflow = template.get('workflow', {})
    if 'workflow' in workflow:
        inner_workflow = workflow['workflow']
        nodes = inner_workflow.get('nodes', [])
    else:
        nodes = workflow.get('nodes', [])
    return nodes

def analyze_template(template_path, template_id):
    try:
        with open(template_path, 'r', encoding='utf-8') as f:
            template = json.load(f)
        
        nodes = extract_nodes_from_template(template)
        

        agent_nodes = [n for n in nodes if is_agent_node(n)]
        agent_count = len(agent_nodes)
        is_multi_agent = agent_count >= 2
        

        community_mcp_nodes = [n for n in nodes if is_community_mcp_node(n)]
        community_mcp_count = len(community_mcp_nodes)
        has_community_mcp = community_mcp_count > 0
        

        matches_criteria = is_multi_agent and has_community_mcp
        
        return {
            'template_id': template_id,
            'is_multi_agent': is_multi_agent,
            'agent_count': agent_count,
            'has_community_mcp': has_community_mcp,
            'community_mcp_count': community_mcp_count,
            'matches_criteria': matches_criteria,
            'agent_node_types': [n.get('type', '') for n in agent_nodes],
            'community_mcp_node_types': [n.get('type', '') for n in community_mcp_nodes],
            'community_mcp_node_names': [n.get('name', '') for n in community_mcp_nodes],
        }
    except Exception as e:
        print(f"Error processing {template_path}: {e}")
        return None

def main():

    base_dir = Path(__file__).parent.parent
    high_risk_file = base_dir / "analyze/data/scan_result/high_risk_domain_templates.json"
    
    print(f"Loading high-risk templates from: {high_risk_file}")
    with open(high_risk_file, 'r', encoding='utf-8') as f:
        high_risk_data = json.load(f)
    

    templates_dir = base_dir / "data/n8n_templates_dump/workflows"
    

    template_info = []
    for domain, templates in high_risk_data['templates_by_domain'].items():
        for template in templates:
            template_id = str(template['template_id'])
            json_file = template.get('json_file', '')
            

            if json_file.startswith('../'):
                template_path = base_dir / json_file[3:]
            else:
                template_path = templates_dir / f"{template_id}.json"
            
            template_info.append({
                'id': template_id,
                'name': template.get('template_name', 'Unknown'),
                'domain': domain,
                'path': template_path,
            })
    
    print(f"Found {len(template_info)} high-risk templates to analyze")
    

    results = []
    stats = {
        'total': len(template_info),
        'multi_agent': 0,
        'has_community_mcp': 0,
        'both': 0,
    }
    
    matching_templates = []
    
    for info in template_info:
        if not info['path'].exists():
            continue
        
        result = analyze_template(info['path'], info['id'])
        if result:
            results.append(result)
            
            if result['is_multi_agent']:
                stats['multi_agent'] += 1
            if result['has_community_mcp']:
                stats['has_community_mcp'] += 1
            if result['matches_criteria']:
                stats['both'] += 1
                matching_templates.append({
                    'template_id': info['id'],
                    'template_name': info['name'],
                    'domain': info['domain'],
                    'agent_count': result['agent_count'],
                    'community_mcp_count': result['community_mcp_count'],
                    'community_mcp_nodes': result['community_mcp_node_types'],
                    'community_mcp_node_names': result['community_mcp_node_names'],
                })
    

    print("\n" + "="*80)
    print("RESULTS")
    print("="*80)
    print(f"Total high-risk templates analyzed: {len(results)}")
    print(f"Multi-agent templates (2+ agents): {stats['multi_agent']}")
    print(f"Templates with community MCP nodes: {stats['has_community_mcp']}")
    print(f"Templates with BOTH multi-agent AND community MCP: {stats['both']}")
    
    if matching_templates:
        print("\n" + "="*80)
        print("MATCHING TEMPLATES (Multi-agent + Community MCP)")
        print("="*80)
        for template in matching_templates:
            print(f"\nTemplate ID: {template['template_id']}")
            print(f"Name: {template['template_name']}")
            print(f"Domain: {template['domain']}")
            print(f"Agent count: {template['agent_count']}")
            print(f"Community MCP node count: {template['community_mcp_count']}")
            print(f"Community MCP node types: {template['community_mcp_nodes']}")
            print(f"Community MCP node names: {template['community_mcp_node_names']}")
    

    output_file = base_dir / "analyze/data/scan_result/high_risk_multi_agent_mcp.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'statistics': stats,
            'matching_templates': matching_templates,
            'all_results': results,
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults saved to: {output_file}")

if __name__ == '__main__':
    main()
