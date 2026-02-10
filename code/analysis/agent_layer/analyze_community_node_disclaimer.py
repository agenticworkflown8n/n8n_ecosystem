#!/usr/bin/env python3
"""
Count templates that use community nodes but lack a self-hosted-only disclaimer.
"""

import json
import csv
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Any

OFFICIAL_NODE_PREFIXES = [
    'n8n-nodes-base.',
    '@n8n/n8n-nodes-base.',
    '@n8n/n8n-nodes-langchain.',
]

DISCLAIMER_KEYWORDS = [
    'self-hosted only',
    'self-hosted',
    'self hosted only',
    'self hosted',
    'not available in n8n cloud',
    'not available in cloud',
    'cloud not supported',
    'requires self-hosting',
    'self-hosting required',
]

def is_community_node(node_type: str) -> bool:
    if not node_type:
        return False
    for prefix in OFFICIAL_NODE_PREFIXES:
        if node_type.startswith(prefix):
            return False
    if "@custom/" in node_type:
        return True
    if node_type.startswith("@") and not node_type.startswith("@n8n/"):
        return True
    if node_type.startswith("n8n-nodes-") and not node_type.startswith("n8n-nodes-base"):
        return True
    return False

def has_disclaimer(text: str) -> bool:
    if not text:
        return False
    
    text_lower = text.lower()
    for keyword in DISCLAIMER_KEYWORDS:
        if keyword.lower() in text_lower:
            return True
    
    return False

def extract_sticky_notes(workflow_data: Dict) -> List[str]:
    sticky_notes = []
    workflow = workflow_data.get("workflow", {})
    if isinstance(workflow, dict):
        for node in workflow.get("nodes", []):
            if not isinstance(node, dict):
                continue
            t = (node.get("type") or "").lower()
            if "sticky" not in t and "note" not in t:
                continue
            params = node.get("parameters", {})
            if isinstance(params, dict):
                content = params.get("content") or params.get("text") or params.get("note")
                if content:
                    sticky_notes.append(str(content))
    return sticky_notes

def analyze_templates():
    templates_dir = Path("data/n8n_templates_dump/workflows")
    community_nodes_csv = Path('data/fetch_result/n8n_nodes_final_2025-11-15_11-36-26.csv')
    
    if not templates_dir.exists():
        print(f"Error: {templates_dir} not found")
        return
    templates_with_community_nodes = []
    templates_with_disclaimer = []
    templates_without_disclaimer = []
    
    template_files = list(templates_dir.glob('*.json'))
    print(f"\nAnalyzing {len(template_files)} templates...")
    
    processed = 0
    for template_file in template_files:
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            workflow = data.get('workflow', {})
            template_id = str(workflow.get('id', template_file.stem))
            template_name = workflow.get('name', '')
            description = workflow.get("description", "")
            workflow_nodes = workflow.get("workflow", {}).get("nodes", [])
            uses_community_nodes = False
            community_node_types = []
            
            for node in workflow_nodes:
                if isinstance(node, dict):
                    node_type = node.get('type', '')
                    if is_community_node(node_type):
                        uses_community_nodes = True
                        community_node_types.append(node_type)
            
            if uses_community_nodes:
                templates_with_community_nodes.append({
                    'template_id': template_id,
                    'template_name': template_name,
                    'community_nodes': list(set(community_node_types)),
                })
                has_desc_disclaimer = has_disclaimer(description)
                sticky_notes = extract_sticky_notes(data)
                has_sticky_disclaimer = any(has_disclaimer(note) for note in sticky_notes)
                
                if has_desc_disclaimer or has_sticky_disclaimer:
                    templates_with_disclaimer.append(template_id)
                else:
                    templates_without_disclaimer.append({
                        'template_id': template_id,
                        'template_name': template_name,
                        'community_nodes': list(set(community_node_types)),
                    })
            
            processed += 1
            if processed % 500 == 0:
                print(f"Processed {processed}/{len(template_files)} templates...")
                
        except Exception as e:
            print(f"Error processing {template_file}: {e}")
            continue
    total_with_community = len(templates_with_community_nodes)
    total_with_disclaimer = len(templates_with_disclaimer)
    total_without_disclaimer = len(templates_without_disclaimer)
    
    print(f"\n=== Community Node Disclaimer Compliance Analysis ===")
    print(f"Total templates analyzed: {len(template_files)}")
    print(f"Templates using community nodes: {total_with_community}")
    print(f"Templates with disclaimer: {total_with_disclaimer}")
    print(f"Templates without disclaimer: {total_without_disclaimer}")
    
    if total_with_community > 0:
        compliance_rate = (total_with_disclaimer / total_with_community * 100)
        non_compliance_rate = (total_without_disclaimer / total_with_community * 100)
        print(f"\nCompliance rate: {compliance_rate:.1f}%")
        print(f"Non-compliance rate: {non_compliance_rate:.1f}%")
    output_file = Path("data/scan_result/community_node_disclaimer_analysis.json")
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump({
            'total_templates': len(template_files),
            'templates_with_community_nodes': total_with_community,
            'templates_with_disclaimer': total_with_disclaimer,
            'templates_without_disclaimer': total_without_disclaimer,
            'compliance_rate': round(total_with_disclaimer / total_with_community * 100, 1) if total_with_community > 0 else 0,
            'non_compliance_rate': round(total_without_disclaimer / total_with_community * 100, 1) if total_with_community > 0 else 0,
            'templates_without_disclaimer_details': templates_without_disclaimer,
        }, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults saved to {output_file}")
    if templates_without_disclaimer:
        print(f"\n=== Sample Templates Without Disclaimer (first 10) ===")
        for i, template in enumerate(templates_without_disclaimer[:10], 1):
            print(f"{i}. Template {template['template_id']}: {template['template_name']}")
            print(f"   Community nodes: {', '.join(template['community_nodes'][:3])}")
    
    return {
        'total_with_community': total_with_community,
        'total_with_disclaimer': total_with_disclaimer,
        'total_without_disclaimer': total_without_disclaimer,
    }

if __name__ == '__main__':
    analyze_templates()

