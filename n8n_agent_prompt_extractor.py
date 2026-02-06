import json
import csv
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
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
    "@n8n/n8n-nodes-langchain.vectorStoreQdrant",
    "@n8n/n8n-nodes-langchain.vectorStorePinecone",
    "@n8n/n8n-nodes-langchain.vectorStoreInMemory",
    "@n8n/n8n-nodes-langchain.vectorStoreSupabase",
    "@n8n/n8n-nodes-langchain.vectorStoreMilvus",
    "@n8n/n8n-nodes-langchain.vectorStoreRedis",
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
    prompts = []
    params = node.get("parameters", {})
    if "text" in params and params["text"]:
        prompts.append({
            "field": "text",
            "content": str(params["text"]).strip()
        })
    if "prompt" in params and params["prompt"]:
        prompts.append({
            "field": "prompt",
            "content": str(params["prompt"]).strip()
        })
    if "systemMessage" in params and params["systemMessage"]:
        prompts.append({
            "field": "systemMessage",
            "content": str(params["systemMessage"]).strip()
        })
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
    if "messages" in params:
        messages = params["messages"]
        if isinstance(messages, dict) and "values" in messages:
            for i, msg in enumerate(messages.get("values", [])):
                if isinstance(msg, dict):
                    if "content" in msg and msg["content"]:
                        prompts.append({
                            "field": f"messages.values[{i}].content",
                            "content": str(msg["content"]).strip()
                        })
                    if "text" in msg and msg["text"]:
                        prompts.append({
                            "field": f"messages.values[{i}].text",
                            "content": str(msg["text"]).strip()
                        })
        elif isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict):
                    if "content" in msg and msg["content"]:
                        prompts.append({
                            "field": f"messages[{i}].content",
                            "content": str(msg["content"]).strip()
                        })
                    if "text" in msg and msg["text"]:
                        prompts.append({
                            "field": f"messages[{i}].text",
                            "content": str(msg["text"]).strip()
                        })
    return prompts
def extract_all_prompts(template_dir: Path) -> Dict[str, Any]:
    templates = []
    total_nodes = 0
    total_prompts = 0
    template_files = sorted(template_dir.glob("*.json"))
    print(f"Processing {len(template_files)} template files...")
    for template_file in template_files:
        try:
            with template_file.open('r', encoding='utf-8') as f:
                template_data = json.load(f)
            workflow_meta = template_data.get("workflow", {})
            template_id = workflow_meta.get("id") or template_file.stem
            template_name = workflow_meta.get("name", "Unknown")
            workflow = workflow_meta.get("workflow", workflow_meta)
            nodes = workflow.get("nodes", [])
            agent_nodes = []
            for node in nodes:
                node_type = node.get("type", "")
                if node_type in LLM_NODE_TYPES:
                    prompts = extract_prompts_from_node(node)
                    if prompts:
                        agent_nodes.append({
                            "node_name": node.get("name", "unknown"),
                            "node_type": node_type,
                            "prompts": prompts
                        })
                        total_prompts += len(prompts)
            if agent_nodes:
                templates.append({
                    "template_id": str(template_id),
                    "template_name": template_name,
                    "agent_count": len(agent_nodes),
                    "agent_nodes": agent_nodes
                })
                total_nodes += len(agent_nodes)
        except Exception as e:
            print(f"Error processing template {template_file.name}: {e}")
            continue
    return {
        "extraction_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_templates_scanned": len(template_files),
            "templates_with_agents": len(templates),
            "total_agent_nodes": total_nodes,
            "total_prompts": total_prompts,
            "llm_node_types": LLM_NODE_TYPES
        },
        "templates": templates
    }
def main():
    base_dir = Path(__file__).parent.parent
    template_dir = base_dir / "data" / "n8n_templates_dump" / "latest" / "workflows"
    output_dir = base_dir / "data" / "scan_result"
    output_dir.mkdir(parents=True, exist_ok=True)
    if not template_dir.exists():
        print(f"Error: Template directory does not exist: {template_dir}")
        return
    print("=" * 80)
    print("Extracting all AI Agent and LLM node prompts")
    print("=" * 80)
    result = extract_all_prompts(template_dir)
    output_file = output_dir / "all_agent_prompts.json"
    with output_file.open('w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n✓ Saved complete data to: {output_file}")
    print(f"  File size: {output_file.stat().st_size / 1024 / 1024:.2f} MB")
    csv_file = output_dir / "all_agent_prompts_summary.csv"
    with csv_file.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            "Template ID", "Template Name", "Node Name", "Node Type",
            "Prompt Field", "Prompt Length", "Prompt Preview"
        ])
        for template in result["templates"]:
            template_id = template["template_id"]
            template_name = template["template_name"]
            for node in template["agent_nodes"]:
                node_name = node["node_name"]
                node_type = node["node_type"]
                for prompt in node["prompts"]:
                    field = prompt["field"]
                    content = prompt["content"]
                    length = len(content)
                    preview = content[:200].replace('\n', ' ').replace('\r', ' ')
                    writer.writerow([
                        template_id, template_name, node_name, node_type,
                        field, length, preview
                    ])
    print(f"✓ Saved CSV summary to: {csv_file}")
    md_file = output_dir / "all_agent_prompts_report.md"
    with md_file.open('w', encoding='utf-8') as f:
        f.write("# AI Agent Prompt Extraction Report\n\n")
        f.write(f"**Extraction Time**: {result['extraction_metadata']['timestamp']}\n\n")
        f.write(f"**Total Templates Scanned**: {result['extraction_metadata']['total_templates_scanned']}\n\n")
        f.write(f"**Templates with AI Agent/LLM**: {result['extraction_metadata']['templates_with_agents']}\n\n")
        f.write(f"**Total AI Agent/LLM Nodes**: {result['extraction_metadata']['total_agent_nodes']}\n\n")
        f.write(f"**Total Prompts**: {result['extraction_metadata']['total_prompts']}\n\n")
        from collections import Counter
        node_types = Counter()
        for template in result["templates"]:
            for node in template["agent_nodes"]:
                node_types[node["node_type"]] += 1
        f.write("\n## Node Type Distribution\n\n")
        f.write("| Node Type | Count |\n")
        f.write("|---------|------|\n")
        for node_type, count in node_types.most_common():
            f.write(f"| {node_type} | {count} |\n")
        prompt_fields = Counter()
        for template in result["templates"]:
            for node in template["agent_nodes"]:
                for prompt in node["prompts"]:
                    prompt_fields[prompt["field"]] += 1
        f.write("\n## Prompt Field Distribution\n\n")
        f.write("| Field | Count |\n")
        f.write("|------|------|\n")
        for field, count in prompt_fields.most_common():
            f.write(f"| {field} | {count} |\n")
        f.write("\n## Top 20 Templates by AI Agent Node Count\n\n")
        f.write("| Template ID | Template Name | AI Agent Node Count |\n")
        f.write("|--------|---------|----------------|\n")
        sorted_templates = sorted(
            result["templates"],
            key=lambda x: x["agent_count"],
            reverse=True
        )[:20]
        for template in sorted_templates:
            f.write(f"| {template['template_id']} | {template['template_name']} | {template['agent_count']} |\n")
    print(f"✓ Saved Markdown report to: {md_file}")
    print("\n" + "=" * 80)
    print("Extraction Statistics")
    print("=" * 80)
    print(f"Total templates scanned: {result['extraction_metadata']['total_templates_scanned']}")
    print(f"Templates with AI Agent/LLM: {result['extraction_metadata']['templates_with_agents']}")
    print(f"Total AI Agent/LLM nodes: {result['extraction_metadata']['total_agent_nodes']}")
    print(f"Total prompts: {result['extraction_metadata']['total_prompts']}")
    from collections import Counter
    node_types = Counter()
    for template in result["templates"]:
        for node in template["agent_nodes"]:
            node_types[node["node_type"]] += 1
    print(f"\nNode type distribution:")
    for node_type, count in node_types.most_common():
        print(f"  {node_type}: {count}")
if __name__ == "__main__":
    main()