#!/usr/bin/env python3
"""
Analyze RAG (Retrieval-Augmented Generation) usage in high-risk domain templates.
"""

import json
from pathlib import Path
from collections import defaultdict

# RAG-related node types
RAG_NODE_TYPES = [
    # LangChain retrieval nodes
    "@n8n/n8n-nodes-langchain.chainRetrievalQa",
    "@n8n/n8n-nodes-langchain.retrievalQa",
    
    # Vector stores
    "n8n-nodes-base.pinecone",
    "n8n-nodes-base.weaviate",
    "n8n-nodes-base.chroma",
    "n8n-nodes-base.qdrant",
    "n8n-nodes-base.milvus",
    "n8n-nodes-base.vectorStore",
    
    # Embedding nodes
    "n8n-nodes-base.openAiEmbeddings",
    "n8n-nodes-base.embedding",
    
    # Document loaders
    "@n8n/n8n-nodes-langchain.documentLoader",
    "@n8n/n8n-nodes-langchain.documentLoaderText",
    "@n8n/n8n-nodes-langchain.documentLoaderPdf",
    "@n8n/n8n-nodes-langchain.documentLoaderCsv",
    
    # Text splitters
    "@n8n/n8n-nodes-langchain.textSplitter",
    
    # Memory with retrieval
    "@n8n/n8n-nodes-langchain.memoryBufferWindow",
    "@n8n/n8n-nodes-langchain.memoryBuffer",
    
    # Other retrieval-related
    "@n8n/n8n-nodes-langchain.retriever",
    "@n8n/n8n-nodes-langchain.vectorStore",
]

def has_rag_nodes(workflow_nodes):
    """Check if workflow contains RAG-related nodes"""
    for node in workflow_nodes:
        node_type = node.get('type', '')
        if any(rag_type in node_type for rag_type in RAG_NODE_TYPES):
            return True
    return False

def main():
    base_dir = Path(__file__).parent.parent
    
    # Load high-risk template IDs
    high_risk_file = base_dir / "analyze/data/scan_result/high_risk_domain_templates.json"
    print("Loading high-risk domain templates...")
    with open(high_risk_file, 'r', encoding='utf-8') as f:
        high_risk_data = json.load(f)
    
    # Get unique template IDs
    template_ids = set()
    for domain, templates in high_risk_data['templates_by_domain'].items():
        for template in templates:
            template_ids.add(str(template['template_id']))
    
    print(f"Found {len(template_ids)} unique high-risk templates")
    
    # Load template files
    workflows_dir = base_dir / "data/n8n_templates_dump/latest/workflows"
    if not workflows_dir.exists():
        workflows_dir = base_dir / "data/n8n_templates_dump/20251201_120007/workflows"
    
    print(f"Scanning templates in {workflows_dir}...")
    
    rag_stats = {
        'total_templates': 0,
        'templates_with_rag': 0,
        'templates_without_rag': 0,
        'rag_by_domain': defaultdict(lambda: {'total': 0, 'with_rag': 0})
    }
    
    processed = 0
    not_found = 0
    
    # Create mapping from template_id to domains
    template_to_domains = {}
    for domain, templates in high_risk_data['templates_by_domain'].items():
        for template in templates:
            template_id = str(template['template_id'])
            if template_id not in template_to_domains:
                template_to_domains[template_id] = []
            template_to_domains[template_id].append(domain)
    
    for template_id in template_ids:
        json_file = workflows_dir / f"{template_id}.json"
        if not json_file.exists():
            not_found += 1
            continue
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                template_data = json.load(f)
            
            workflow = template_data.get('workflow', {})
            workflow_nodes = workflow.get('workflow', {}).get('nodes', [])
            
            has_rag = has_rag_nodes(workflow_nodes)
            
            rag_stats['total_templates'] += 1
            if has_rag:
                rag_stats['templates_with_rag'] += 1
            else:
                rag_stats['templates_without_rag'] += 1
            
            # Count by domain
            if template_id in template_to_domains:
                for domain in template_to_domains[template_id]:
                    rag_stats['rag_by_domain'][domain]['total'] += 1
                    if has_rag:
                        rag_stats['rag_by_domain'][domain]['with_rag'] += 1
            
            processed += 1
            
            if processed % 50 == 0:
                print(f"Processed {processed}/{len(template_ids)} templates...")
        
        except Exception as e:
            print(f"Error processing {template_id}: {e}")
            continue
    
    print(f"\nProcessed {processed} templates, {not_found} not found")
    
    # Calculate statistics
    total = rag_stats['total_templates']
    with_rag = rag_stats['templates_with_rag']
    without_rag = rag_stats['templates_without_rag']
    rag_percentage = (with_rag / total * 100) if total > 0 else 0
    
    print("\n" + "="*80)
    print("RAG Usage Statistics for High-Risk Domain Templates")
    print("="*80)
    print(f"Total templates analyzed: {total}")
    print(f"Templates with RAG: {with_rag} ({rag_percentage:.2f}%)")
    print(f"Templates without RAG: {without_rag} ({100-rag_percentage:.2f}%)")
    
    print("\nRAG Usage by Domain:")
    domain_names = {
        'administration_justice_democratic_processes': 'Administration of Justice and Democratic Processes',
        'education_vocational_training': 'Education and Vocational Training',
        'employment_workers_management': 'Employment and Workers Management',
        'essential_private_public_services': 'Essential Private and Public Services',
        'migration_asylum_border_control': 'Migration, Asylum and Border Control',
        'biometric_identification': 'Biometric Identification',
        'law_enforcement': 'Law Enforcement'
    }
    
    for domain, stats in sorted(rag_stats['rag_by_domain'].items()):
        if stats['total'] > 0:
            domain_name = domain_names.get(domain, domain)
            rag_rate = (stats['with_rag'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {domain_name}: {stats['with_rag']}/{stats['total']} ({rag_rate:.2f}%)")
    
    # Save results
    output_file = base_dir / "analyze/data/scan_result/rag_usage_statistics.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        'analysis_timestamp': str(Path(__file__).stat().st_mtime),
        'total_templates_analyzed': total,
        'templates_with_rag': with_rag,
        'templates_without_rag': without_rag,
        'rag_adoption_rate': rag_percentage,
        'rag_by_domain': {
            domain: {
                'domain_name': domain_names.get(domain, domain),
                'total_templates': stats['total'],
                'templates_with_rag': stats['with_rag'],
                'rag_adoption_rate': (stats['with_rag'] / stats['total'] * 100) if stats['total'] > 0 else 0
            }
            for domain, stats in rag_stats['rag_by_domain'].items()
        }
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults saved to {output_file}")

if __name__ == '__main__':
    main()
