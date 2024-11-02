import os
import json
from openai import OpenAI
import random
import time
import argparse

# Setup OpenAI connection
client = OpenAI(base_url="http://192.168.0.210:443/v1", api_key="lm-studio")

# Persistent memory storage for session-level data and findings
session_memory = {
    "target_info": {
        "target": None,  # Will store IP or network range
        "scan_type": "host"  # 'host' for single IP, 'network' for range
    },
    "findings": [],
    "commands_executed": [],
    "targets": {}
}

# Execute command with error handling and result capture
def execute_command(command):
    # Add command validation/sanitization
    ALLOWED_COMMANDS = ['nmap', 'nikto', 'gobuster', 'wfuzz', 'sqlmap']
    
    try:
        # Basic command validation
        base_command = command.split()[0]
        if base_command not in ALLOWED_COMMANDS:
            return f"Command '{base_command}' not in allowed list: {ALLOWED_COMMANDS}"
            
        print(f"\n[+] Executing: {command}")
        result = os.popen(command).read().strip()
        print(f"[+] Output:\n{result}")
        return result
    except Exception as e:
        result = f"Error executing command: {str(e)}"
        print(f"[-] {result}")
        return result

# Update memory to include command results and findings
def update_memory(command, result):
    session_memory["commands_executed"].append(command)
    if "open port" in result or "vulnerability" in result:
        session_memory["findings"].append({"command": command, "result": result})
    # Extract target info if new target found
    if "IP" in result or "service" in result:
        # Parsing out relevant info for demo purposes
        target_info = parse_target_info(result)
        session_memory["targets"].update(target_info)

def parse_target_info(result):
    # Mock parsing - would include more sophisticated regex parsing in a real setup
    target_info = {}
    if "IP" in result:
        target_info["IP"] = result.split("IP ")[1].split(" ")[0]  # Simple extraction example
    if "service" in result:
        target_info["service"] = result.split("service ")[1].split(" ")[0]
    return target_info

def interpret_result(result):
    # Expanded interpretation logic with NLP placeholders
    if "open port" in result:
        return "Enumerate services on open ports"
    elif "403" in result or "401" in result:
        return "Attempt credential brute force"
    elif "SQL" in result or "MySQL" in result:
        return "Attempt SQL injection testing"
    elif "vulnerability" in result:
        return "Analyze vulnerability for exploitation"
    elif "firewall" in result or "blocked" in result:
        return "Consider alternate scanning techniques"
    else:
        return "Continue reconnaissance"

def assess_risk(command, result):
    # Multi-dimensional risk scoring for complex findings
    risk_score = 0
    if "critical vulnerability" in result:
        risk_score += 5
    elif "open port" in result:
        risk_score += 3
    elif "authentication error" in result:
        risk_score += 2
    # Adjust risk goals based on findings
    if risk_score >= 5:
        return "High-risk target found; escalate actions"
    elif risk_score >= 3:
        return "Moderate risk; deepen reconnaissance"
    else:
        return interpret_result(result)

def generate_report():
    # Summarize findings for review
    report = json.dumps(session_memory, indent=2)
    print("\n[+] Final Report:\n", report)

def free_thinking_pentest(goal, target):
    # Validate and set target
    if not target:
        print("[!] Error: Target IP or network range must be specified")
        return
    
    session_memory["target_info"]["target"] = target
    session_memory["target_info"]["scan_type"] = "network" if "/" in target else "host"
    
    system_prompt = f"""You are an advanced penetration testing assistant. Provide commands in the following JSON format:
{{
    "command": "actual command to execute",
    "purpose": "brief description of command purpose",
    "expected_output": "what to look for in the results"
}}

Available commands: nmap, nikto, gobuster, wfuzz, sqlmap
Target: {target}
Current Goal: {goal}

Previous findings and command history are provided for context."""

    while True:  # Remove arbitrary limit, let user control execution
        try:
            # Get next command from AI
            response = client.chat.completions.create(
                model="RichardErkhov/WhiteRabbitNeo_-_WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-gguf",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"Previous findings: {json.dumps(session_memory['findings'])}\nLast command result: {result if 'result' in locals() else 'None'}\nSuggest next command:"}
                ],
                temperature=0.3,
                max_tokens=150  # Add this to limit response length
            )

            # Take only the first valid JSON object from the response
            response_text = response.choices[0].message.content.strip()
            first_json_end = response_text.find('}') + 1
            if first_json_end > 0:
                response_text = response_text[:first_json_end]

            # Parse AI response as JSON
            try:
                ai_response = json.loads(response_text)
                command = ai_response["command"]
                purpose = ai_response["purpose"]
                expected = ai_response["expected_output"]
                
                print(f"\n[*] AI Suggestion:")
                print(f"Purpose: {purpose}")
                print(f"Command: {command}")
                print(f"Expected Output: {expected}")
                
                # Ask user for confirmation
                user_input = input("\nExecute this command? (y/n/q to quit): ").lower()
                if user_input == 'q':
                    break
                elif user_input != 'y':
                    continue
                
                # Execute and process results
                result = execute_command(command)
                update_memory(command, result)
                next_goal = assess_risk(command, result)
                
                # Update system prompt with new goal
                system_prompt = f"{next_goal}\nTarget: {session_memory['target_info']['target']}"
                
            except json.JSONDecodeError:
                print("[!] Error: AI provided invalid response format")
                continue
                
        except KeyboardInterrupt:
            print("\n[*] User interrupted execution")
            break

    generate_report()

# Update the script execution with command line arguments
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Automated Penetration Testing Script')
    parser.add_argument('target', help='Target IP or network range (e.g., 192.168.1.1 or 192.168.1.0/24)')
    args = parser.parse_args()
    
    initial_goal = "Start reconnaissance on target and identify further actions."
    free_thinking_pentest(initial_goal, args.target)
