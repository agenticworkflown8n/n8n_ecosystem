#!/usr/bin/env python3
"""
Extract templates containing high-risk domain keywords based on EU AI Act Annex III.
This script identifies templates that operate in high-risk domains as defined in 
Table 10 (tab:annex3_high_risk_domains) in Appendix B.

The 8 high-risk domains according to Annex III are:
1. Biometric identification
2. Critical infrastructure
3. Education and vocational training
4. Employment and workers' management
5. Essential private and public services
6. Law enforcement
7. Migration, asylum and border control
8. Administration of justice and democratic processes
"""

import json
import csv
import re
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Define high-risk domain keywords based on EU AI Act Annex III (Article 6(2))
# Mapping to the 8 domains defined in the regulation with detailed subcategories
HIGH_RISK_DOMAIN_KEYWORDS = {
    'biometric_identification': [
        # 1. Biometrics: remote identification, categorisation, emotion recognition
        # (a) Remote biometric identification systems
        'remote biometric identification', 'biometric identification', 'biometric recognition',
        'face recognition', 'facial recognition', 'fingerprint recognition', 'iris recognition',
        'voice recognition', 'gait recognition', 'retina scan', 'palm print recognition',
        # (b) Biometric categorisation (sensitive/protected attributes)
        'biometric categorisation', 'biometric categorization', 'biometric classification',
        'biometric attribute inference', 'biometric trait inference',
        # (c) Emotion recognition
        'emotion recognition', 'facial expression recognition', 'emotion detection',
        'sentiment recognition', 'affective computing',
        # General biometric terms
        'biometric data', 'biometric template', 'biometric matching', 'biometric enrollment',
        'biometric authentication', 'biometric verification'
    ],
    'critical_infrastructure': [
        # 2. Critical infrastructure: safety components in digital infrastructure, road traffic, utilities
        'critical infrastructure', 'critical digital infrastructure', 'safety component',
        'safety system', 'safety-critical system',
        # Road traffic
        'road traffic', 'traffic management', 'traffic control', 'traffic safety',
        'traffic monitoring', 'traffic system',
        # Utilities: water, gas, heating, electricity
        'water supply', 'water management', 'water infrastructure', 'water system',
        'gas supply', 'gas infrastructure', 'gas management', 'gas system',
        'heating supply', 'heating infrastructure', 'heating system',
        'electricity supply', 'power grid', 'electrical grid', 'power infrastructure',
        'electricity management', 'power system',
        # Other infrastructure
        'telecommunications infrastructure', 'transportation system', 'railway safety',
        'aviation safety', 'air traffic control', 'maritime safety', 'nuclear safety',
        'dam safety', 'bridge monitoring', 'infrastructure safety', 'critical system',
        'SCADA', 'industrial control', 'process control', 'utility management'
    ],
    'education_vocational_training': [
        # 3. Education and vocational training
        # (a) Determine access/admission or assign persons to institutions
        'admission', 'student admission', 'university admission', 'college admission',
        'school admission', 'educational admission', 'admission decision',
        'assign to educational institution', 'assign to school', 'assign to university',
        # (b) Evaluate learning outcomes (including steering learning process)
        'learning evaluation', 'learning outcome', 'learning assessment', 'academic evaluation',
        'student assessment', 'educational assessment', 'learning analytics',
        'academic performance', 'grade evaluation', 'academic grading', 'student evaluation',
        # (c) Assess appropriate level of education
        'level assessment', 'educational level', 'skill assessment', 'competency assessment',
        'education level assessment', 'academic level',
        # (d) Monitor/detect prohibited behaviour during tests
        'test monitoring', 'exam monitoring', 'proctoring', 'online proctoring',
        'test proctoring', 'exam proctoring', 'monitor test', 'detect cheating',
        'prohibited behaviour', 'test behavior', 'exam behavior',
        # Additional keywords from previous scan
        'student', 'course', 'curriculum', 'academic', 'university', 
        'enrollment', 'grade', 'school', 'scholarship', 'education',
        'vocational training', 'vocational assessment', 'certification exam'
    ],
    'employment_workers_management': [
        # 4. Employment, workers' management and access to self-employment
        # (a) Recruitment/selection: targeted job ads, filter applications, evaluate candidates
        'recruitment', 'job recruitment', 'candidate selection', 'hiring',
        'employee selection', 'job application', 'filter job application',
        'targeted job advertisement', 'targeted job ad', 'job ad targeting',
        'evaluate candidate', 'candidate evaluation', 'applicant evaluation',
        'job application analysis', 'resume screening', 'CV screening',
        # (b) Decisions affecting work relationships: promotion, termination, task allocation, performance monitoring
        'work-related decision', 'workplace decision', 'promotion decision',
        'termination decision', 'work relationship', 'workplace relationship',
        'promotion', 'termination', 'workplace termination', 'employee termination',
        'allocate task', 'task allocation', 'work allocation',
        'performance monitoring', 'employee monitoring', 'workforce monitoring',
        'performance evaluation', 'employee evaluation', 'performance review',
        'workplace surveillance', 'productivity monitoring', 'attendance monitoring',
        'employee assessment', 'workforce analytics', 'employee analytics',
        'behavior monitoring', 'workplace behavior', 'employee behavior'
    ],
    'essential_private_public_services': [
        # 5. Essential private and public services
        # (a) Evaluate eligibility for public assistance benefits/services (including healthcare)
        'public benefits', 'benefits evaluation', 'welfare evaluation', 'social benefits',
        'public assistance', 'assistance benefits', 'eligibility evaluation',
        'public service', 'government service', 'citizen service', 'public administration',
        'social security', 'unemployment benefits', 'disability benefits',
        'healthcare service', 'public healthcare', 'healthcare eligibility',
        # Healthcare keywords (from previous scan - essential services include healthcare)
        'healthcare', 'health', 'medical', 'patient', 'clinic', 'doctor', 'symptom',
        'hospital', 'pharmacy', 'HIPAA', 'PHI', 'diagnosis', 'treatment',
        'prescription', 'medication', 'disease', 'illness', 'therapy',
        'medical report', 'health monitoring', 'health assistant', 'medical advice',
        # (b) Evaluate creditworthiness/credit score (except fraud detection)
        'credit scoring', 'credit assessment', 'credit evaluation', 'creditworthiness',
        'credit score', 'loan scoring', 'credit rating', 'credit check',
        # (c) Risk assessment and pricing for life/health insurance
        'insurance', 'insurance claim', 'insurance evaluation', 'underwriting',
        'life insurance', 'health insurance', 'insurance risk assessment',
        'insurance pricing', 'insurance premium', 'insurance underwriting',
        # (d) Emergency services: evaluate/classify calls, dispatch, triage
        'emergency services', 'emergency response', '911', 'emergency dispatch',
        'ambulance dispatch', 'fire department', 'police dispatch',
        'emergency call', 'emergency call evaluation', 'emergency call classification',
        'emergency triage', 'patient triage', 'healthcare triage',
        'first response', 'emergency first response', 'emergency healthcare'
    ],
    'law_enforcement': [
        # 6. Law enforcement (as permitted under Union/national law)
        # (a) Assess risk of becoming victim of criminal offences
        'law enforcement', 'police', 'victim risk assessment', 'criminal victim risk',
        'risk of victim', 'victim assessment',
        # (b) Polygraphs or similar tools
        'polygraph', 'lie detector', 'polygraph test',
        # (c) Evaluate reliability of evidence
        'evidence evaluation', 'evidence analysis', 'evidence reliability',
        'evidence assessment', 'forensic evidence', 'criminal evidence',
        # (d) Assess risk of offending/re-offending, personality traits, criminal behavior
        'offender profiling', 'criminal profiling', 'risk of offending',
        'risk of re-offending', 'reoffending risk', 'offending risk',
        'personality trait', 'criminal behavior', 'past criminal behavior',
        # (e) Profiling of natural persons
        'criminal profiling', 'suspect profiling', 'person profiling',
        # General law enforcement terms
        'criminal investigation', 'crime investigation', 'suspect identification',
        'criminal record', 'forensic analysis', 'crime scene', 'investigation',
        'criminal justice', 'law enforcement agency', 'police investigation',
        'criminal case', 'criminal prosecution'
    ],
    'migration_asylum_border_control': [
        # 7. Migration, asylum and border control (as permitted under Union/national law)
        # (a) Polygraphs or similar tools
        'migration polygraph', 'asylum polygraph', 'border polygraph', 'polygraph',
        # (b) Assess risk: security, irregular migration, health
        'migration risk', 'asylum risk', 'border risk', 'security risk',
        'irregular migration', 'migration risk assessment', 'asylum risk assessment',
        'border risk assessment', 'risk assessment', 'assess risk',
        'health risk', 'migration health risk', 'security risk assessment',
        'risk evaluation', 'risk analysis', 'threat assessment',
        'migration threat', 'border threat', 'asylum threat',
        # (c) Examine applications for asylum/visa/residence permits
        'migration', 'asylum', 'asylum application', 'asylum examination',
        'visa examination', 'visa application', 'residence permit',
        'asylum eligibility', 'visa eligibility', 'residence permit application',
        'asylum status', 'visa status', 'immigration status',
        'asylum seeker', 'visa applicant', 'immigration applicant',
        'asylum claim', 'visa claim', 'immigration claim',
        'asylum review', 'visa review', 'immigration review',
        'asylum process', 'visa process', 'immigration process',
        # (d) Detect/recognize/identify natural persons (except travel document verification)
        'border control', 'border security', 'immigration', 'immigration control',
        'person identification', 'migration identification', 'border identification',
        'identity verification', 'passport verification', 'visa verification',
        'refugee', 'refugee status', 'immigration decision', 'asylum decision',
        'border crossing', 'customs', 'immigration enforcement',
        'migration management', 'asylum management', 'border management',
        'border patrol', 'immigration officer', 'border officer',
        'detect person', 'recognize person', 'identify person',
        'person detection', 'person recognition'
    ],
    'administration_justice_democratic_processes': [
        # 8. Administration of justice and democratic processes
        # (a) Assist judicial authority: research/interpret facts and law, apply law, alternative dispute resolution
        'judicial assistance', 'judicial system', 'court system', 'legal system',
        'judicial authority', 'assist judicial', 'judicial research',
        'interpret facts', 'interpret law', 'apply law', 'legal interpretation',
        'alternative dispute resolution', 'ADR', 'dispute resolution',
        'judicial decision', 'legal decision', 'court decision', 'judge',
        'judiciary', 'legal proceeding', 'court proceeding',
        'legal case', 'court case', 'judicial case',
        # (b) Influence election/referendum outcome or voting behavior
        'election', 'election influence', 'influence election', 'election outcome',
        'referendum', 'referendum influence', 'influence referendum',
        'voting', 'voting behavior', 'voting behaviour', 'influence voting',
        'ballot', 'electoral process', 'democratic process',
        'voter', 'candidate', 'political campaign', 'election monitoring',
        'vote counting', 'electoral influence',
        # Additional keywords from previous scan (legal domain)
        'legal', 'law', 'compliance', 'contract', 'attorney', 'lawyer', 
        'litigation', 'lawsuit', 'legal document', 'jurisdiction', 
        'legal advice', 'legal counsel'
    ]
}

def write_markdown_report(domain_templates, templates_with_high_risk_domains, 
                         total_templates, output_md, extraction_timestamp):
    """
    Write markdown report in the same format as the previous scan results.
    
    Args:
        domain_templates: Dictionary mapping domain names to list of template info dicts
        templates_with_high_risk_domains: Total count of templates with high-risk domains
        total_templates: Total templates analyzed
        output_md: Output markdown file path
        extraction_timestamp: Timestamp string
    """
    with open(output_md, 'w', encoding='utf-8') as f:
        f.write("# High-Risk Domain Templates with AI Agents/LLMs (EU AI Act Annex III)\n\n")
        f.write("**FILTERED**: Only templates with AI agent or LLM nodes are included\n\n")
        f.write("This list contains templates operating in high-risk domains as defined in ")
        f.write("EU AI Act Annex III (Table 10) that use AI agents or LLM nodes.\n")
        f.write("Use this list to test templates on the official n8n platform.\n\n")
        
        percentage = (templates_with_high_risk_domains / total_templates * 100) if total_templates > 0 else 0
        f.write(f"**Total Templates**: {templates_with_high_risk_domains}\n")
        f.write(f"**Percentage**: {percentage:.2f}%\n")
        f.write(f"**Extraction Date**: {extraction_timestamp}\n\n")
        f.write("---\n\n")
        
        # Domain name mapping for display
        domain_display_names = {
            'biometric_identification': 'BIOMETRIC IDENTIFICATION',
            'critical_infrastructure': 'CRITICAL INFRASTRUCTURE',
            'education_vocational_training': 'EDUCATION AND VOCATIONAL TRAINING',
            'employment_workers_management': 'EMPLOYMENT AND WORKERS MANAGEMENT',
            'essential_private_public_services': 'ESSENTIAL PRIVATE AND PUBLIC SERVICES',
            'law_enforcement': 'LAW ENFORCEMENT',
            'migration_asylum_border_control': 'MIGRATION, ASYLUM AND BORDER CONTROL',
            'administration_justice_democratic_processes': 'ADMINISTRATION OF JUSTICE AND DEMOCRATIC PROCESSES'
        }
        
        # Sort domains by template count (descending)
        sorted_domains = sorted(domain_templates.items(), key=lambda x: len(x[1]), reverse=True)
        
        for domain, templates in sorted_domains:
            display_name = domain_display_names.get(domain, domain.upper().replace('_', ' '))
            f.write(f"## {display_name} Domain\n\n")
            f.write(f"**Total**: {len(templates)} templates\n\n")
            f.write("| Template ID | Template Name | Views | Matched Keywords |\n")
            f.write("|------------|---------------|-------|------------------|\n")
            
            # Sort templates by views (descending)
            sorted_templates = sorted(templates, key=lambda x: x.get('views', 0), reverse=True)
            
            for template in sorted_templates:
                template_id = template.get('template_id', '')
                template_name = template.get('template_name', '')
                # Truncate long names
                if len(template_name) > 60:
                    template_name = template_name[:57] + "..."
                views = template.get('views', 0)
                
                # Format matched keywords
                matched_keywords = template.get('matched_keywords', {})
                keyword_list = []
                for dom, keywords in matched_keywords.items():
                    keyword_list.extend(keywords[:3])  # Limit to first 3 keywords per domain
                keywords_str = ", ".join(keyword_list[:5])  # Limit to 5 total keywords
                
                f.write(f"| {template_id} | {template_name} | {views} | {keywords_str} |\n")
            
            f.write("\n---\n\n")

def has_ai_agent_or_llm_nodes(workflow_data):
    """
    Check if workflow contains AI agent or LLM nodes.
    
    Args:
        workflow_data: Workflow JSON data
        
    Returns:
        bool: True if workflow contains AI agent or LLM nodes
    """
    workflow = workflow_data.get('workflow', {})
    workflow_nodes = workflow.get('workflow', {})
    nodes = workflow_nodes.get('nodes', [])
    
    # AI agent and LLM node type patterns
    ai_patterns = [
        'langchain.agent',
        'langchain.openAi',
        'langchain.anthropic',
        'langchain.googleGemini',
        'langchain.chainLlm',
        'langchain.lmChat',
        'openAi',
        'openai',
        'anthropic',
        'gemini',
        'llm',
        'agent'
    ]
    
    for node in nodes:
        node_type = node.get('type', '').lower()
        for pattern in ai_patterns:
            if pattern.lower() in node_type:
                return True
    
    return False

def load_templates_with_agents():
    """
    Load template IDs that contain AI agents/LLMs from all_agent_prompts.json.
    
    Returns:
        set: Set of template IDs as strings
    """
    prompts_file = Path('data/scan_result/all_agent_prompts.json')
    if not prompts_file.exists():
        print("Warning: all_agent_prompts.json not found, will check nodes directly")
        return None
    
    try:
        with open(prompts_file, 'r', encoding='utf-8') as f:
            prompts_data = json.load(f)
        
        templates_with_agents = set()
        for template in prompts_data.get('templates', []):
            template_id = template.get('template_id')
            if template_id:
                templates_with_agents.add(str(template_id))
        
        return templates_with_agents
    except Exception as e:
        print(f"Warning: Could not load agent templates list: {e}")
        return None

def extract_templates_with_high_risk_domains(workflows_dir, output_csv, output_json):
    """
    Extract templates containing sensitive domain keywords.
    Only includes templates that have AI agent or LLM nodes.
    
    Args:
        workflows_dir: Path to directory containing template JSON files
        output_csv: Output CSV file path
        output_json: Output JSON file path
    """
    workflows_dir = Path(workflows_dir)
    
    if not workflows_dir.exists():
        print(f"Error: Directory {workflows_dir} does not exist")
        return
    
    # Load templates with agents (if available)
    templates_with_agents_set = load_templates_with_agents()
    if templates_with_agents_set:
        print(f"Loaded {len(templates_with_agents_set)} templates with AI agents/LLMs from all_agent_prompts.json")
    
    # Statistics
    domain_templates = defaultdict(list)
    template_domains = {}  # template_id -> list of domains
    total_templates = 0
    templates_with_high_risk_domains = 0
    templates_without_agents = 0
    
    print("Scanning templates for high-risk domain keywords (EU AI Act Annex III)...")
    print(f"Searching in: {workflows_dir}\n")
    
    # Process all JSON files
    json_files = list(workflows_dir.glob("*.json"))
    print(f"Found {len(json_files)} template files to analyze\n")
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            total_templates += 1
            workflow = data.get('workflow', {})
            template_id = workflow.get('id', json_file.stem)
            template_name = workflow.get('name', '')
            description = workflow.get('description', '')
            
            # Check if template contains AI agent or LLM nodes
            workflow_nodes = workflow.get('workflow', {}).get('nodes', [])
            has_agent_or_llm = False
            
            # AI agent and LLM node type patterns
            agent_llm_patterns = [
                r'@n8n/n8n-nodes-langchain\.agent',
                r'@n8n/n8n-nodes-langchain\.openAi',
                r'@n8n/n8n-nodes-langchain\.anthropic',
                r'@n8n/n8n-nodes-langchain\.chainLlm',
                r'@n8n/n8n-nodes-langchain\.googleGemini',
                r'@n8n/n8n-nodes-langchain\.lmChat',
                r'n8n-nodes-base\.openAi',
                r'n8n-nodes-base\.openai',
                r'n8n-nodes-base\.anthropic',
            ]
            
            for node in workflow_nodes:
                node_type = node.get('type', '')
                for pattern in agent_llm_patterns:
                    if re.search(pattern, node_type, re.IGNORECASE):
                        has_agent_or_llm = True
                        break
                if has_agent_or_llm:
                    break
            
            # Skip templates without AI agent or LLM nodes
            if not has_agent_or_llm:
                continue
            
            # Separate title and description for weighted matching
            title_lower = template_name.lower()
            desc_lower = description.lower()
            
            # Check for high-risk domain keywords with title weighting
            found_domains = []
            matched_keywords = defaultdict(list)
            domain_scores = defaultdict(float)  # Score for each domain
            
            for domain, keywords in HIGH_RISK_DOMAIN_KEYWORDS.items():
                for keyword in keywords:
                    # Use word boundary matching to avoid false positives
                    pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                    
                    # Check title (higher weight)
                    title_match = re.search(pattern, title_lower, re.IGNORECASE)
                    # Check description (lower weight)
                    desc_match = re.search(pattern, desc_lower, re.IGNORECASE)
                    
                    if title_match:
                        # Title match gets full weight (1.0)
                        domain_scores[domain] += 1.0
                        if domain not in found_domains:
                            found_domains.append(domain)
                        matched_keywords[domain].append(keyword)
                    elif desc_match:
                        # Description match gets weight (0.5)
                        domain_scores[domain] += 0.5
                        # Add to found_domains if score is significant (single description match = 0.5)
                        if domain_scores[domain] >= 0.5 and domain not in found_domains:
                            found_domains.append(domain)
                            matched_keywords[domain].append(keyword)
            
            # Additional validation: require title match for certain high-risk domains
            # These domains are more critical and need stronger evidence
            critical_domains = [
                'biometric_identification', 'critical_infrastructure', 
                'law_enforcement', 'migration_asylum_border_control'
            ]
            # Legal/justice domain needs lower threshold as legal keywords are common and valid
            legal_domains = ['administration_justice_democratic_processes']
            validated_domains = []
            for domain in found_domains:
                if domain in critical_domains:
                    # Check if we have title match or strong description evidence
                    if domain_scores[domain] >= 1.0:  # Title match or 2 description matches
                        validated_domains.append(domain)
                    elif domain_scores[domain] >= 0.5:  # Single description match (with 0.5 weight)
                        validated_domains.append(domain)
                    # Otherwise, skip this domain (false positive likely)
                elif domain in legal_domains:
                    # Legal domain: accept title match or single description match
                    if domain_scores[domain] >= 1.0:  # Title match or 2 description matches
                        validated_domains.append(domain)
                    elif domain_scores[domain] >= 0.5:  # Single description match is acceptable
                        validated_domains.append(domain)
                else:
                    # Less critical domains can rely on description
                    if domain_scores[domain] >= 0.5:  # Single description match
                        validated_domains.append(domain)
            
            found_domains = validated_domains
            
            if found_domains:
                # Check if template has AI agent or LLM nodes
                has_agents = False
                
                # First check the pre-loaded list (faster)
                if templates_with_agents_set:
                    has_agents = str(template_id) in templates_with_agents_set
                else:
                    # Fallback: check nodes directly
                    has_agents = has_ai_agent_or_llm_nodes(data)
                
                if not has_agents:
                    templates_without_agents += 1
                    continue  # Skip templates without agents/LLMs
                
                templates_with_high_risk_domains += 1
                template_info = {
                    'template_id': template_id,
                    'template_name': template_name,
                    'description': description[:200] + '...' if len(description) > 200 else description,
                    'domains': found_domains,
                    'matched_keywords': {k: v for k, v in matched_keywords.items()},
                    'json_file': str(json_file),
                    'views': workflow.get('views', 0),
                    'created_at': workflow.get('createdAt', ''),
                    'categories': [cat.get('name', '') for cat in workflow.get('categories', [])]
                }
                
                for domain in found_domains:
                    domain_templates[domain].append(template_info)
                
                template_domains[template_id] = {
                    'domains': found_domains,
                    'template_name': template_name,
                    'json_file': str(json_file)
                }
        
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue
        
        # Progress indicator
        if total_templates % 1000 == 0:
            print(f"Processed {total_templates} templates...")
    
    # Generate summary statistics
    print(f"\n{'='*80}")
    print("EXTRACTION SUMMARY")
    print(f"{'='*80}")
    print(f"Total templates analyzed: {total_templates}")
    print(f"Templates with high-risk domains (Annex III): {templates_with_high_risk_domains}")
    print(f"Templates excluded (no AI agents/LLMs): {templates_without_agents}")
    if total_templates > 0:
        print(f"Percentage: {templates_with_high_risk_domains/total_templates*100:.2f}%\n")
    else:
        print("Percentage: 0.00%\n")
    
    print("Templates by domain:")
    for domain, templates in sorted(domain_templates.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"  {domain}: {len(templates)} templates")
    
    # Write CSV output
    print(f"\nWriting results to {output_csv}...")
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Template ID', 'Template Name', 'Domains', 'Matched Keywords',
            'Views', 'Created At', 'Categories', 'Description', 'JSON File Path'
        ])
        
        for template_id, info in sorted(template_domains.items(), key=lambda x: x[0]):
            template_name = info['template_name']
            domains = ', '.join(info['domains'])
            
            # Find full template info
            full_info = None
            for domain in info['domains']:
                for t in domain_templates[domain]:
                    if t['template_id'] == template_id:
                        full_info = t
                        break
                if full_info:
                    break
            
            if full_info:
                matched_keywords_str = '; '.join([
                    f"{k}: {', '.join(v)}" for k, v in full_info['matched_keywords'].items()
                ])
                writer.writerow([
                    template_id,
                    template_name,
                    domains,
                    matched_keywords_str,
                    full_info.get('views', 0),
                    full_info.get('created_at', ''),
                    ', '.join(full_info.get('categories', [])),
                    full_info.get('description', ''),
                    full_info.get('json_file', '')
                ])
    
    # Write JSON output
    print(f"Writing detailed results to {output_json}...")
    output_data = {
        'extraction_timestamp': datetime.now().isoformat(),
        'total_templates_analyzed': total_templates,
        'templates_with_high_risk_domains': templates_with_high_risk_domains,
        'eu_ai_act_annex_iii_domains': list(HIGH_RISK_DOMAIN_KEYWORDS.keys()),
        'statistics': {
            domain: len(templates) for domain, templates in domain_templates.items()
        },
        'templates_by_domain': {
            domain: templates for domain, templates in domain_templates.items()
        },
        'all_templates': list(template_domains.values())
    }
    
    with open(output_json, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    # Write Markdown output
    extraction_timestamp = datetime.now().isoformat()
    output_md = output_json.replace('.json', '.md')
    print(f"Writing markdown report to {output_md}...")
    write_markdown_report(domain_templates, templates_with_high_risk_domains, 
                        total_templates, output_md, extraction_timestamp)
    
    print(f"\n✓ Extraction complete!")
    print(f"  CSV: {output_csv}")
    print(f"  JSON: {output_json}")
    print(f"  Markdown: {output_md}")


if __name__ == '__main__':
    import sys
    
    # Default paths
    if len(sys.argv) > 1:
        workflows_dir = sys.argv[1]
    else:
        workflows_dir = "../data/n8n_templates_dump/workflows"
        if not Path(workflows_dir).exists():
            workflows_dir = "../data/n8n_templates_dump/20251201_120007/workflows"
    
    output_csv = "data/scan_result/high_risk_domain_templates.csv"
    output_json = "data/scan_result/high_risk_domain_templates.json"
    
    # Create output directory if it doesn't exist
    Path(output_csv).parent.mkdir(parents=True, exist_ok=True)
    
    extract_templates_with_high_risk_domains(workflows_dir, output_csv, output_json)

