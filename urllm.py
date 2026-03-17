import os
import re
import json
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from litellm import completion

def fetch_and_parse(url: str) -> dict:
    """
    Deterministically fetches and parses the URL to extract a technical footprint.
    This grounds our GenAI analysis in factual data and saves token context.
    """
    print(f"[*] Deterministically analyzing URL: {url}")
    try:
        # Standard headers to avoid basic blocks
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        parsed_url = urlparse(url)
        base_domain = parsed_url.netloc
        
        # 1. Extract Meta Frameworks & Generators
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        generator = meta_generator['content'] if meta_generator else 'Unknown'
        
        # 2. Extract Scripts (identifying tech stack like React, Vue, Analytics, etc.)
        scripts = soup.find_all('script')
        script_sources = [s.get('src') for s in scripts if s.get('src')]
        
        # Identify Third-Party Data Consumers (Graph sink nodes)
        third_party_domains = set()
        for src in script_sources:
            if src.startswith('http'):
                domain = urlparse(src).netloc
                if domain and domain != base_domain:
                    third_party_domains.add(domain)
        
        # Look for inline data fetching patterns (simplistic regex for data flow)
        inline_scripts = [s.string for s in scripts if s.string]
        api_endpoints = set()
        for inline in inline_scripts:
            # Look for fetch('...') or axios.get('...') patterns
            matches = re.findall(r'(?:fetch|axios\.(?:get|post|put|delete))\(["\'](.*?)["\']\)', inline)
            api_endpoints.update(matches)

        # 3. Extract Forms (Data Ingestion Points & Suspicious Flows)
        forms = soup.find_all('form')
        form_data = []
        for form in forms:
            action = form.get('action', 'Same Page')
            
            # Check for cross-origin data posting
            full_action = urljoin(url, action) if action != 'Same Page' else url
            action_domain = urlparse(full_action).netloc
            is_cross_origin = bool(action_domain and action_domain != base_domain)
            
            method = form.get('method', 'GET').upper()
            
            # Analyze inputs for covert tracking (hidden fields)
            inputs = [{'name': inp.get('name'), 'type': inp.get('type', 'text')} for inp in form.find_all('input') if inp.get('name')]
            hidden_inputs = [inp['name'] for inp in inputs if inp['type'] == 'hidden']
            
            form_data.append({
                "action": action, 
                "method": method, 
                "is_cross_origin": is_cross_origin,
                "input_count": len(inputs),
                "hidden_inputs": hidden_inputs
            })

        # 4. Extract CSS Frameworks (Bootstrap, Tailwind, etc.)
        links = soup.find_all('link', rel='stylesheet')
        stylesheets = [l.get('href') for l in links if l.get('href')]

        return {
            "url": url,
            "base_domain": base_domain,
            "status_code": response.status_code,
            "generator": generator,
            "third_party_consumers": list(third_party_domains)[:20], # Trackers / Ad networks
            "inline_api_calls_found": list(api_endpoints)[:10],
            "forms": form_data,
            "stylesheets": stylesheets[:10]
        }

    except Exception as e:
        return {"error": str(e)}

def summarize_architecture_with_ai(footprint: dict) -> str:
    """
    Uses GenAI to reason about the deterministic footprint.
    Uses LiteLLM to support any backend model (OpenAI, Anthropic, Gemini, etc.).
    """
    print("[*] Passing extracted footprint to LLM for architectural analysis...")
    
    # Allow overriding the model via environment variable, defaulting to Gemini
    model_name = os.environ.get("LLM_MODEL", "gemini/gemini-2.5-flash")
    
    prompt = f"""
    You are an expert Principal Security & Software Architect.
    I have performed a deterministic static analysis of a web page and extracted its technical footprint. 
    Treat this architecture as a directed graph where data flows from the origin domain to various consumer nodes.
    
    Here is the extracted JSON data:
    {json.dumps(footprint, indent=2)}
    
    Based on this data, please provide a concise, professional summary covering:
    1. Technical Stack components (Frontend frameworks, styling, CMS, etc.).
    2. Data Flow & External Consumers (Analyze the `third_party_consumers`. What ad networks, trackers, or SaaS tools are sinking data from this page?).
    3. Suspicious or Anomalous Patterns (Flag `is_cross_origin` form submissions, excessive `hidden_inputs` used for tracking/CSRF bypass, or strange API endpoints. Are there obvious privacy/security risks?).
    4. Potential SDLC insights (What kind of backend/deployment architecture does this frontend suggest?).
    
    Do not hallucinate features not hinted at by the data, but use your architectural experience to infer the likely setup.
    """
    
    try:
        # LiteLLM uses the standard OpenAI-style message format
        response = completion(
            model=model_name,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error during AI generation: {str(e)}"

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python url_analyzer.py <URL>")
        print("Example: python url_analyzer.py https://news.ycombinator.com")
        print("\nNote: Set the LLM_MODEL env var to change providers (e.g., 'gpt-4o', 'claude-3-5-sonnet-20240620').")
        print("      Ensure you have the corresponding API key set (e.g., OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY).")
        sys.exit(1)
        
    target_url = sys.argv[1]
    
    # Step 1: Deterministic Analysis
    extracted_data = fetch_and_parse(target_url)
    
    if "error" in extracted_data:
        print(f"Failed to parse URL: {extracted_data['error']}")
    else:
        # Step 2: GenAI Summarization
        print("# URLLM\n")
        print("## DETERMINISTIC DATA EXTRACTED:")
        print("```json")
        print(json.dumps(extracted_data, indent=2))
        print("```\n")
        summary = summarize_architecture_with_ai(extracted_data)
        print("## GEN AI ARCHITECTURE SUMMARY:")
        print(summary)
