#!/usr/bin/env python3
"""
Analyze EU AI Act compliance for high-risk domain templates.
Extracts prompts from 775 high-risk templates and checks compliance with 4 standards:
1. Risk and limitation disclaimers (Article 9(2)(d))
2. Bias and discrimination risk statements (Article 10(2)(f)(g))
3. Output interpretability statements (Article 13(1))
4. Over-reliance warnings (Article 14(4)(b))
"""

import json
import re
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime
from typing import Dict, List, Any, Set

# Load high-risk template IDs
HIGH_RISK_TEMPLATES_FILE = "analyze/data/scan_result/high_risk_domain_templates.json"
ALL_PROMPTS_FILE = "data/scan_result/all_agent_prompts.json"
WORKFLOWS_DIR = "data/n8n_templates_dump/latest/workflows"

# EU AI Act Compliance Standards (from Table 3)
COMPLIANCE_STANDARDS = {
    'risk_limitation_disclaimers': {
        'article': 'Article 9(2)(d)',
        'keywords': [
            'risk', 'limitation', 'disclaimer', 'warning',
            'not responsible', 'no warranty', 'use at your own risk',
            'limitations', 'risks', 'may not be accurate',
            'errors may occur', 'no guarantee', 'as-is',
            'without warranty', 'not liable', 'disclaim',
            'limitation of liability', 'no assurance'
        ]
    },
    'bias_discrimination_statements': {
        'article': 'Article 10(2)(f)(g)',
        'keywords': [
            'bias', 'discrimination', 'discriminatory', 'unfair',
            'may contain bias', 'potential bias', 'bias detection',
            'bias mitigation', 'avoid discrimination', 'fair',
            'equitable', 'unbiased', 'prejudice', 'stereotyp',
            'may discriminate', 'discrimination risk'
        ]
    },
    'output_interpretability': {
        'article': 'Article 13(1)',
        'keywords': [
            'interpret', 'interpretability', 'explain', 'explanation',
            'understand', 'transparent', 'transparency', 'clarity',
            'may not be clear', 'output may vary', 'results may differ',
            'uncertain', 'confidence', 'reliability', 'accuracy',
            'may be incorrect', 'verify', 'validate', 'check'
        ]
    },
    'over_reliance_warnings': {
        'article': 'Article 14(4)(b)',
        'keywords': [
            'over-reliance', 'overreliance', 'do not rely solely',
            'not a substitute', 'should not replace', 'supplementary',
            'human oversight', 'human review', 'verify with',
            'consult professional', 'not professional advice',
            'not medical advice', 'not legal advice', 'not financial advice',
            'not a replacement', 'use with caution', 'supplement',
            'additional verification', 'human judgment', 'expert review'
        ]
    }
}

# All LLM node types that may contain prompts
LLM_NODE_TYPES = [
    "@n8n/n8n-nodes-langchain.agent",
    "@n8n/n8n-nodes-langchain.openAi",
    "@n8n/n8n-nodes-langchain.anthropic",
    "@n8n/n8n-nodes-langchain.chainLlm",
    "@n8n/n8n-nodes-langchain.informationExtractor",
    "@n8n/n8n-nodes-langchain.agentTool",
    "@n8n/n8n-nodes-langchain.googleGemini",
    "@n8n/n8n-nodes-langchain.googleGeminiTool",
    "@n8n/n8n-nodes-langchain.chainRetrievalQa",
    "@n8n/n8n-nodes-langchain.outputParserAutofixing",
    "@n8n/n8n-nodes-langchain.outputParserStructured",
    "@n8n/n8n-nodes-langchain.guardrails",
    "n8n-nodes-base.openAi",
    "n8n-nodes-base.openai",
    "n8n-nodes-base.anthropic",
    "@n8n/n8n-nodes-langchain.lmChatOpenAi",
    "@n8n/n8n-nodes-langchain.lmChatAnthropic",
    "@n8n/n8n-nodes-langchain.lmChatGoogleGemini",
    "@n8n/n8n-nodes-langchain.lmChatAzureOpenAi",
    "@n8n/n8n-nodes-langchain.lmChatGroq",
    "@n8n/n8n-nodes-langchain.lmChatMistralCloud",
    "@n8n/n8n-nodes-langchain.lmChatOpenRouter",
    "@n8n/n8n-nodes-langchain.lmChatXAiGrok",
    "@n8n/n8n-nodes-langchain.chat",
    "@n8n/n8n-nodes-langchain.chatTrigger",
    "@n8n/n8n-nodes-langchain.chainSummarization",
    "@n8n/n8n-nodes-langchain.textClassifier",
]

def extract_prompts_from_node(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract all prompt fields from a node"""
    prompts = []
    params = node.get("parameters", {})
    
    # Extract text field
    if "text" in params and params["text"]:
        prompts.append({
            "field": "text",
            "content": str(params["text"]).strip()
        })
    
    # Extract prompt field
    if "prompt" in params and params["prompt"]:
        prompts.append({
            "field": "prompt",
            "content": str(params["prompt"]).strip()
        })
    
    # Extract systemMessage field
    if "systemMessage" in params and params["systemMessage"]:
        prompts.append({
            "field": "systemMessage",
            "content": str(params["systemMessage"]).strip()
        })
    
    # Extract options fields
    if "options" in params and isinstance(params["options"], dict):
        options = params["options"]
        if "systemMessage" in options and options["systemMessage"]:
            prompts.append({
                "field": "options.systemMessage",
                "content": str(options["systemMessage"]).strip()
            })
        if "prompt" in options and options["prompt"]:
            prompts.append({
                "field": "options.prompt",
                "content": str(options["prompt"]).strip()
            })
    
    # Extract messages field
    if "messages" in params:
        messages = params["messages"]
        if isinstance(messages, dict) and "values" in messages:
            for i, msg in enumerate(messages.get("values", [])):
                if isinstance(msg, dict):
                    if "content" in msg and msg["content"]:
                        prompts.append({
                            "field": f"messages[{i}].content",
                            "content": str(msg["content"]).strip()
                        })
        elif isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict) and "content" in msg and msg["content"]:
                    prompts.append({
                        "field": f"messages[{i}].content",
                        "content": str(msg["content"]).strip()
                    })
    
    return prompts

def check_compliance_standard(prompt_text: str, standard: str) -> Dict[str, Any]:
    """Check if prompt text contains keywords for a compliance standard"""
    keywords = COMPLIANCE_STANDARDS[standard]['keywords']
    found_keywords = []
    
    prompt_lower = prompt_text.lower()
    for keyword in keywords:
        # Use word boundary matching
        pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            found_keywords.append(keyword)
    
    return {
        'compliant': len(found_keywords) > 0,
        'matched_keywords': found_keywords,
        'article': COMPLIANCE_STANDARDS[standard]['article']
    }

def analyze_template_compliance(template_data: Dict[str, Any], template_id: str) -> Dict[str, Any]:
    """Analyze a single template for EU AI Act compliance"""
    workflow = template_data.get('workflow', {})
    workflow_nodes = workflow.get('workflow', {}).get('nodes', [])
    
    all_prompts = []
    compliance_results = {
        'risk_limitation_disclaimers': {'compliant': False, 'matched_keywords': []},
        'bias_discrimination_statements': {'compliant': False, 'matched_keywords': []},
        'output_interpretability': {'compliant': False, 'matched_keywords': []},
        'over_reliance_warnings': {'compliant': False, 'matched_keywords': []}
    }
    
    # Extract prompts from all LLM nodes
    for node in workflow_nodes:
        node_type = node.get('type', '')
        if any(llm_type in node_type for llm_type in LLM_NODE_TYPES):
            prompts = extract_prompts_from_node(node)
            for prompt_info in prompts:
                prompt_text = prompt_info['content']
                if prompt_text and len(prompt_text.strip()) > 0:
                    all_prompts.append({
                        'node_type': node_type,
                        'field': prompt_info['field'],
                        'content': prompt_text
                    })
                    
                    # Check each compliance standard
                    for standard in compliance_results.keys():
                        result = check_compliance_standard(prompt_text, standard)
                        if result['compliant']:
                            compliance_results[standard]['compliant'] = True
                            compliance_results[standard]['matched_keywords'].extend(result['matched_keywords'])
    
    # Remove duplicate keywords
    for standard in compliance_results:
        compliance_results[standard]['matched_keywords'] = list(set(compliance_results[standard]['matched_keywords']))
    
    return {
        'template_id': template_id,
        'template_name': workflow.get('name', ''),
        'total_prompts': len(all_prompts),
        'prompts': all_prompts,
        'compliance': compliance_results
    }

def main():
    # Load high-risk template IDs
    base_dir = Path(__file__).parent.parent
    high_risk_file = base_dir / HIGH_RISK_TEMPLATES_FILE
    print("Loading high-risk template data...")
    with open(high_risk_file, 'r', encoding='utf-8') as f:
        high_risk_data = json.load(f)
    
    # Get unique template IDs
    template_ids = set()
    for domain, templates in high_risk_data['templates_by_domain'].items():
        for template in templates:
            template_ids.add(str(template['template_id']))
    
    print(f"Found {len(template_ids)} unique high-risk templates")
    
    # Load template files
    base_dir = Path(__file__).parent.parent
    workflows_dir = base_dir / WORKFLOWS_DIR
    if not workflows_dir.exists():
        workflows_dir = base_dir / "data/n8n_templates_dump/20251201_120007/workflows"
    if not workflows_dir.exists():
        workflows_dir = base_dir / "data/n8n_templates_dump/latest/workflows"
    
    print(f"Scanning templates in {workflows_dir}...")
    
    results = []
    processed = 0
    not_found = 0
    
    for template_id in template_ids:
        json_file = workflows_dir / f"{template_id}.json"
        if not json_file.exists():
            not_found += 1
            continue
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                template_data = json.load(f)
            
            result = analyze_template_compliance(template_data, template_id)
            results.append(result)
            processed += 1
            
            if processed % 50 == 0:
                print(f"Processed {processed}/{len(template_ids)} templates...")
        
        except Exception as e:
            print(f"Error processing {template_id}: {e}")
            continue
    
    print(f"\nProcessed {processed} templates, {not_found} not found")
    
    # Calculate statistics
    total_templates = len(results)
    compliance_stats = {
        'risk_limitation_disclaimers': 0,
        'bias_discrimination_statements': 0,
        'output_interpretability': 0,
        'over_reliance_warnings': 0
    }
    
    for result in results:
        for standard in compliance_stats.keys():
            if result['compliance'][standard]['compliant']:
                compliance_stats[standard] += 1
    
    # Generate summary
    print("\n" + "="*80)
    print("EU AI Act Compliance Analysis Summary")
    print("="*80)
    print(f"Total high-risk templates analyzed: {total_templates}")
    print(f"\nCompliance by Standard:")
    for standard, count in compliance_stats.items():
        percentage = (count / total_templates * 100) if total_templates > 0 else 0
        article = COMPLIANCE_STANDARDS[standard]['article']
        print(f"  {article}: {count}/{total_templates} ({percentage:.2f}%)")
    
    # Calculate non-compliance
    print(f"\nNon-Compliance:")
    for standard, count in compliance_stats.items():
        non_compliant = total_templates - count
        percentage = (non_compliant / total_templates * 100) if total_templates > 0 else 0
        article = COMPLIANCE_STANDARDS[standard]['article']
        print(f"  {article}: {non_compliant}/{total_templates} ({percentage:.2f}%)")
    
    # Templates with zero compliance
    zero_compliance = sum(1 for r in results if not any(r['compliance'][s]['compliant'] for s in compliance_stats.keys()))
    print(f"\nTemplates with zero compliance standards: {zero_compliance}/{total_templates} ({zero_compliance/total_templates*100:.2f}%)")
    
    # Save results
    base_dir = Path(__file__).parent.parent
    output_file = base_dir / "analyze/data/scan_result/eu_ai_act_compliance_analysis.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    output_data = {
        'analysis_timestamp': datetime.now().isoformat(),
        'total_templates_analyzed': total_templates,
        'compliance_statistics': compliance_stats,
        'non_compliance_statistics': {
            standard: total_templates - count 
            for standard, count in compliance_stats.items()
        },
        'zero_compliance_count': zero_compliance,
        'compliance_standards': {
            standard: {
                'article': COMPLIANCE_STANDARDS[standard]['article'],
                'description': standard.replace('_', ' ').title()
            }
            for standard in COMPLIANCE_STANDARDS.keys()
        },
        'results': results
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\nResults saved to {output_file}")
    
    # Generate CSV summary
    csv_file = base_dir / "analyze/data/scan_result/eu_ai_act_compliance_summary.csv"
    import csv
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Template ID', 'Template Name', 'Total Prompts',
            'Risk/Limitation Disclaimers', 'Bias/Discrimination Statements',
            'Output Interpretability', 'Over-Reliance Warnings',
            'Compliant Standards Count'
        ])
        
        for result in results:
            compliance_count = sum(1 for s in compliance_stats.keys() 
                                  if result['compliance'][s]['compliant'])
            writer.writerow([
                result['template_id'],
                result['template_name'],
                result['total_prompts'],
                'Yes' if result['compliance']['risk_limitation_disclaimers']['compliant'] else 'No',
                'Yes' if result['compliance']['bias_discrimination_statements']['compliant'] else 'No',
                'Yes' if result['compliance']['output_interpretability']['compliant'] else 'No',
                'Yes' if result['compliance']['over_reliance_warnings']['compliant'] else 'No',
                compliance_count
            ])
    
    print(f"CSV summary saved to {csv_file}")

if __name__ == '__main__':
    main()
