#!/usr/bin/env python3
"""
Analyze EU AI Act compliance by domain category.
Calculate non-compliance rates for each of the 7 high-risk domains across 4 compliance standards.
"""

import json
from pathlib import Path
from collections import defaultdict

def main():
    base_dir = Path(__file__).parent.parent
    
    # Load high-risk domain templates
    high_risk_file = base_dir / "analyze/data/scan_result/high_risk_domain_templates.json"
    print("Loading high-risk domain templates...")
    with open(high_risk_file, 'r', encoding='utf-8') as f:
        high_risk_data = json.load(f)
    
    # Load compliance analysis results
    compliance_file = base_dir / "analyze/data/scan_result/eu_ai_act_compliance_analysis.json"
    print("Loading compliance analysis results...")
    with open(compliance_file, 'r', encoding='utf-8') as f:
        compliance_data = json.load(f)
    
    # Create mapping from template_id to domains
    template_to_domains = {}
    for domain, templates in high_risk_data['templates_by_domain'].items():
        for template in templates:
            template_id = str(template['template_id'])
            if template_id not in template_to_domains:
                template_to_domains[template_id] = []
            template_to_domains[template_id].append(domain)
    
    # Create mapping from template_id to compliance results
    template_to_compliance = {}
    for result in compliance_data['results']:
        template_id = result['template_id']
        template_to_compliance[template_id] = result
    
    # Statistics by domain
    domain_stats = defaultdict(lambda: {
        'total_templates': 0,
        'risk_limitation_disclaimers': {'compliant': 0, 'non_compliant': 0},
        'bias_discrimination_statements': {'compliant': 0, 'non_compliant': 0},
        'output_interpretability': {'compliant': 0, 'non_compliant': 0},
        'over_reliance_warnings': {'compliant': 0, 'non_compliant': 0}
    })
    
    # Process each template
    for template_id, domains in template_to_domains.items():
        if template_id not in template_to_compliance:
            continue
        
        compliance_result = template_to_compliance[template_id]
        
        for domain in domains:
            domain_stats[domain]['total_templates'] += 1
            
            # Count compliance for each standard
            if compliance_result['compliance']['risk_limitation_disclaimers']['compliant']:
                domain_stats[domain]['risk_limitation_disclaimers']['compliant'] += 1
            else:
                domain_stats[domain]['risk_limitation_disclaimers']['non_compliant'] += 1
            
            if compliance_result['compliance']['bias_discrimination_statements']['compliant']:
                domain_stats[domain]['bias_discrimination_statements']['compliant'] += 1
            else:
                domain_stats[domain]['bias_discrimination_statements']['non_compliant'] += 1
            
            if compliance_result['compliance']['output_interpretability']['compliant']:
                domain_stats[domain]['output_interpretability']['compliant'] += 1
            else:
                domain_stats[domain]['output_interpretability']['non_compliant'] += 1
            
            if compliance_result['compliance']['over_reliance_warnings']['compliant']:
                domain_stats[domain]['over_reliance_warnings']['compliant'] += 1
            else:
                domain_stats[domain]['over_reliance_warnings']['non_compliant'] += 1
    
    domain_names = {
        'biometric_identification': 'Biometric Identification',
        'critical_infrastructure': 'Critical Infrastructure',
        'education_vocational_training': 'Education & Vocational Training',
        'employment_workers_management': 'Employment & Workers Management',
        'essential_private_public_services': 'Essential Private/Public Services',
        'law_enforcement': 'Law Enforcement',
        'migration_asylum_border_control': 'Migration, Asylum & Border Control',
        'administration_justice_democratic_processes': 'Administration of Justice & Democratic Processes',
    }
    print("\n" + "="*100)
    print("EU AI Act compliance analysis by high-risk domain")
    print("="*100)
    sorted_domains = sorted(domain_stats.items(), key=lambda x: x[1]['total_templates'], reverse=True)
    print(f"\n{'Domain':<30} {'Templates':<10} {'Article 9(2)(d)':<20} {'Article 10(2)(f)(g)':<20} {'Article 13(1)':<20} {'Article 14(4)(b)':<20}")
    print("-" * 100)
    
    for domain, stats in sorted_domains:
        if stats['total_templates'] == 0:
            continue
        
        domain_name = domain_names.get(domain, domain)
        total = stats['total_templates']
        
        # Calculate non-compliance rates
        nc1 = stats['risk_limitation_disclaimers']['non_compliant']
        nc1_rate = (nc1 / total * 100) if total > 0 else 0
        
        nc2 = stats['bias_discrimination_statements']['non_compliant']
        nc2_rate = (nc2 / total * 100) if total > 0 else 0
        
        nc3 = stats['output_interpretability']['non_compliant']
        nc3_rate = (nc3 / total * 100) if total > 0 else 0
        
        nc4 = stats['over_reliance_warnings']['non_compliant']
        nc4_rate = (nc4 / total * 100) if total > 0 else 0
        
        nc1_str = f"{nc1_rate:>6.2f}% ({nc1}/{total})"
        nc2_str = f"{nc2_rate:>6.2f}% ({nc2}/{total})"
        nc3_str = f"{nc3_rate:>6.2f}% ({nc3}/{total})"
        nc4_str = f"{nc4_rate:>6.2f}% ({nc4}/{total})"
        print(f"{domain_name:<30} {total:<10} {nc1_str:<20} {nc2_str:<20} {nc3_str:<20} {nc4_str:<20}")
    
    # Calculate overall totals
    total_templates_all = sum(stats['total_templates'] for _, stats in sorted_domains if stats['total_templates'] > 0)
    total_nc1 = sum(stats['risk_limitation_disclaimers']['non_compliant'] for _, stats in sorted_domains if stats['total_templates'] > 0)
    total_nc2 = sum(stats['bias_discrimination_statements']['non_compliant'] for _, stats in sorted_domains if stats['total_templates'] > 0)
    total_nc3 = sum(stats['output_interpretability']['non_compliant'] for _, stats in sorted_domains if stats['total_templates'] > 0)
    total_nc4 = sum(stats['over_reliance_warnings']['non_compliant'] for _, stats in sorted_domains if stats['total_templates'] > 0)
    
    overall_nc1_rate = (total_nc1 / total_templates_all * 100) if total_templates_all > 0 else 0
    overall_nc2_rate = (total_nc2 / total_templates_all * 100) if total_templates_all > 0 else 0
    overall_nc3_rate = (total_nc3 / total_templates_all * 100) if total_templates_all > 0 else 0
    overall_nc4_rate = (total_nc4 / total_templates_all * 100) if total_templates_all > 0 else 0
    
    # Print summary row
    print("-" * 100)
    overall_nc1_str = f"{overall_nc1_rate:>6.2f}% ({total_nc1}/{total_templates_all})"
    overall_nc2_str = f"{overall_nc2_rate:>6.2f}% ({total_nc2}/{total_templates_all})"
    overall_nc3_str = f"{overall_nc3_rate:>6.2f}% ({total_nc3}/{total_templates_all})"
    overall_nc4_str = f"{overall_nc4_rate:>6.2f}% ({total_nc4}/{total_templates_all})"
    print(f"{'Total':<30} {total_templates_all:<10} {overall_nc1_str:<20} {overall_nc2_str:<20} {overall_nc3_str:<20} {overall_nc4_str:<20}")
    
    # Generate detailed JSON output
    output_data = {
        'analysis_timestamp': compliance_data['analysis_timestamp'],
        'domains': {},
        'overall_summary': {
            'total_templates': total_templates_all,
            'compliance_by_standard': {
                'risk_limitation_disclaimers': {
                    'article': 'Article 9(2)(d)',
                    'compliant': total_templates_all - total_nc1,
                    'non_compliant': total_nc1,
                    'non_compliance_rate': overall_nc1_rate
                },
                'bias_discrimination_statements': {
                    'article': 'Article 10(2)(f)(g)',
                    'compliant': total_templates_all - total_nc2,
                    'non_compliant': total_nc2,
                    'non_compliance_rate': overall_nc2_rate
                },
                'output_interpretability': {
                    'article': 'Article 13(1)',
                    'compliant': total_templates_all - total_nc3,
                    'non_compliant': total_nc3,
                    'non_compliance_rate': overall_nc3_rate
                },
                'over_reliance_warnings': {
                    'article': 'Article 14(4)(b)',
                    'compliant': total_templates_all - total_nc4,
                    'non_compliant': total_nc4,
                    'non_compliance_rate': overall_nc4_rate
                }
            }
        }
    }
    
    for domain, stats in sorted_domains:
        if stats['total_templates'] == 0:
            continue
        
        total = stats['total_templates']
        output_data['domains'][domain] = {
            'domain_name': domain_names.get(domain, domain),
            'total_templates': total,
            'compliance_by_standard': {
                'risk_limitation_disclaimers': {
                    'article': 'Article 9(2)(d)',
                    'compliant': stats['risk_limitation_disclaimers']['compliant'],
                    'non_compliant': stats['risk_limitation_disclaimers']['non_compliant'],
                    'non_compliance_rate': (stats['risk_limitation_disclaimers']['non_compliant'] / total * 100) if total > 0 else 0
                },
                'bias_discrimination_statements': {
                    'article': 'Article 10(2)(f)(g)',
                    'compliant': stats['bias_discrimination_statements']['compliant'],
                    'non_compliant': stats['bias_discrimination_statements']['non_compliant'],
                    'non_compliance_rate': (stats['bias_discrimination_statements']['non_compliant'] / total * 100) if total > 0 else 0
                },
                'output_interpretability': {
                    'article': 'Article 13(1)',
                    'compliant': stats['output_interpretability']['compliant'],
                    'non_compliant': stats['output_interpretability']['non_compliant'],
                    'non_compliance_rate': (stats['output_interpretability']['non_compliant'] / total * 100) if total > 0 else 0
                },
                'over_reliance_warnings': {
                    'article': 'Article 14(4)(b)',
                    'compliant': stats['over_reliance_warnings']['compliant'],
                    'non_compliant': stats['over_reliance_warnings']['non_compliant'],
                    'non_compliance_rate': (stats['over_reliance_warnings']['non_compliant'] / total * 100) if total > 0 else 0
                }
            }
        }
    
    # Save JSON output
    output_file = base_dir / "analyze/data/scan_result/eu_ai_act_compliance_by_domain.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    print(f"\nDetailed results saved to: {output_file}")
    
    # Generate CSV output
    import csv
    csv_file = base_dir / "analyze/data/scan_result/eu_ai_act_compliance_by_domain.csv"
    with open(csv_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Domain (English)', 'Domain (Chinese)', 'Total Templates',
            'Article 9(2)(d) Non-Compliant', 'Article 9(2)(d) Non-Compliance Rate (%)',
            'Article 10(2)(f)(g) Non-Compliant', 'Article 10(2)(f)(g) Non-Compliance Rate (%)',
            'Article 13(1) Non-Compliant', 'Article 13(1) Non-Compliance Rate (%)',
            'Article 14(4)(b) Non-Compliant', 'Article 14(4)(b) Non-Compliance Rate (%)'
        ])
        
        for domain, stats in sorted_domains:
            if stats['total_templates'] == 0:
                continue
            
            total = stats['total_templates']
            domain_name = domain_names.get(domain, domain)
            writer.writerow([
                domain_name,
                total,
                stats['risk_limitation_disclaimers']['non_compliant'],
                round((stats['risk_limitation_disclaimers']['non_compliant'] / total * 100) if total > 0 else 0, 2),
                stats['bias_discrimination_statements']['non_compliant'],
                round((stats['bias_discrimination_statements']['non_compliant'] / total * 100) if total > 0 else 0, 2),
                stats['output_interpretability']['non_compliant'],
                round((stats['output_interpretability']['non_compliant'] / total * 100) if total > 0 else 0, 2),
                stats['over_reliance_warnings']['non_compliant'],
                round((stats['over_reliance_warnings']['non_compliant'] / total * 100) if total > 0 else 0, 2)
            ])
        
        # Add summary row to CSV
        writer.writerow([
            'OVERALL SUMMARY',
            total_templates_all,
            total_nc1,
            round(overall_nc1_rate, 2),
            total_nc2,
            round(overall_nc2_rate, 2),
            total_nc3,
            round(overall_nc3_rate, 2),
            total_nc4,
            round(overall_nc4_rate, 2)
        ])
    
    print(f"CSV results saved to: {csv_file}")

if __name__ == '__main__':
    main()
