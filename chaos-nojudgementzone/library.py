import re
import requests
from openai import OpenAI

def parse_markdown(file_path):
    try:
        with open(file_path, "r") as file:
            content = file.read()
    except FileNotFoundError:
        print(f"Error: Could not find markdown file at {file_path}")
        return {}
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return {}

    # Extract each code block and its title
    pattern = r"### (.*?)\n```(?:c|h)\n(.*?)\n```"  # Updated to handle both .c and .h files
    matches = re.findall(pattern, content, re.DOTALL)

    # Store each title and code snippet in a dictionary
    code_blocks = {title.strip(): code.strip() for title, code in matches}
    return code_blocks

def get_available_snippets(code_blocks):
    """Return a list of available techniques with descriptions"""
    return {
        "Encryption": {
            "AES": {
                "Tiny-AES Library": {
                    "Encryption": "AES Encryption Using The Tiny-AES Library",
                    "Decryption": "AES Decryption Using The Tiny-AES Library"
                },
                "WinAPI": {
                    "Encryption": "AES Encryption Using WinAPIs",
                    "Decryption": "AES Decryption Using WinAPIs"
                },
                "CTAES Library": {
                    "Encryption": "AES Encryption Using The CTAES Library",
                    "Decryption": "AES Decryption Using The CTAES Library"
                }
            },
            "RC4": {
                "Custom": "RC4 Encryption & Decryption Via a Custom RC4 Algorithm",
                "NTAPI": "RC4 Encryption & Decryption Via NTAPI"
            },
            "XOR": {
                "Single-Byte": "XOR Encryption & Decryption Using a Single-Byte Key",
                "Multi-Byte": "XOR Encryption & Decryption Using a Multiple-Byte Key"
            },
            "Vigenere": {
                "ASCII": {
                    "Encryption": "Vigenere String Encryption (ASCII)",
                    "Decryption": "Vigenere String Decryption (ASCII)"
                },
                "Unicode": {
                    "Encryption": "Vigenere String Encryption (Unicode)",
                    "Decryption": "Vigenere String Decryption (Unicode)"
                }
            },
            "Caesar": {
                "ASCII": {
                    "Encryption": "Caesar Cipher String Encryption (ASCII)",
                    "Decryption": "Caesar Cipher String Decryption (ASCII)"
                },
                "Unicode": {
                    "Encryption": "Caesar Cipher String Encryption (Unicode)",
                    "Decryption": "Caesar Cipher String Decryption (Unicode)"
                }
            }
        },
        "Execution": {
            "Fiber": ["Payload Execution Via Fibers", "Payload Execution Via Fibers (2)"],
            "APC": ["Payload Execution Via APC Queues", "APC Queues Execution Via HellsHall"],
            "Thread": {
                "Hijacking": ["Payload Execution Via Thread Hijacking", "Thread Hijacking Via HellsHall"],
                "Callback": [
                    "Payload Execution Via VerifierEnumerateResource Callback Function",
                    "Payload Execution Via CreateTimerQueueTimer Callback Function",
                    "Payload Execution Via EnumChildWindows Callback Function",
                    "Payload Execution Via EnumUILanguagesW Callback Function"
                ]
            }
        },
        "Process Manipulation": {
            "Process Creation": {
                "NtCreateUserProcess": {
                    "Basic": "Process Creation Via NtCreateUserProcess",
                    "Block DLL": [
                        "Process Creation With Block DLL Policy",
                        "Process Creation With Block DLL Policy Enabled (ASCII)",
                        "Process Creation With Block non-Microsoft DLLs Policy Enabled (Unicode)"
                    ],
                    "PPID Spoofing": [
                        "Process Creation With PPID Spoofing",
                        "Process Creation With PPID Spoofing And Block DLL Policy"
                    ]
                }
            },
            "Process Enumeration": {
                "EnumProcesses": "Process Enumeration Via EnumProcesses",
                "NtQuerySystemInformation": "Process Enumeration Via NtQuerySystemInformation",
                "Snapshot": "Process Enumeration Via Snapshot"
            },
            "Process Techniques": {
                "Ghosting": "Process Ghosting",
                "Herpaderping": "Process Herpaderping",
                "Hollowing": "Process Hollowing",
                "Hypnosis": "Process Hypnosis"
            },
            "Process Injection": {
                "Early Bird": [
                    "Early Bird Process Injection (ASCII)",
                    "Early Bird Process Injection (Unicode)"
                ],
                "DLL Injection": {
                    "Local": [
                        "Local DLL Injection (ASCII)",
                        "Local DLL Injection (Unicode)",
                        "Local Mapping Injection"
                    ],
                    "Remote": [
                        "Remote DLL Injection (ASCII)",
                        "Remote DLL Injection (Unicode)"
                    ]
                },
                "Threadless": [
                    "Threadless Injection",
                    "Hardware Breakpoint Threadless Injection (Existing Process)",
                    "Hardware Breakpoint Threadless Injection (New Process)"
                ]
            }
        }
        # ... add other categories similarly
    }

def list_available_options():
    """Print available options with descriptions in a hierarchical structure"""
    snippets = get_available_snippets({})
    print("\nAvailable Techniques:")
    print("-" * 50)
    
    def print_nested_dict(d, indent=0):
        for key, value in d.items():
            print("  " * indent + f"- {key}")
            if isinstance(value, dict):
                print_nested_dict(value, indent + 1)
            elif isinstance(value, list):
                for item in value:
                    print("  " * (indent + 1) + f"- {item}")
            else:
                print("  " * (indent + 1) + f"- {value}")
    
    print_nested_dict(snippets)

def submit_to_ai(code, technique_name):
    """Submit code to AI with specific context for shellcode loader generation"""
    try:
        # Initialize OpenAI client pointing to local LM Studio
        client = OpenAI(
            base_url="http://192.168.0.210:443/v1",  # Consider changing to http://localhost:1234/v1
            api_key="lm-studio"
        )

        # Add error handling and logging for connection
        try:
            # Test connection before making the main request
            response = requests.get(client.base_url)
            print(f"Server status: {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Failed to connect to AI server: {e}")
            return None

        prompt = f"""
        You are tasked with generating a Windows x64 shellcode loader implementation.
        
        REQUIREMENTS:
        1. Target Architecture: Windows x64
        2. Compiler: Microsoft Visual C++ (MSVC)
        3. Input Code Format: C
        4. Purpose: Shellcode loading and execution
        5. Technique to Implement: {technique_name}

        RESPONSE FORMAT REQUIREMENTS:
        1. Respond ONLY with the C code implementation
        2. Include clear comments explaining key functionality
        3. Maintain all necessary includes and definitions
        4. Ensure all functions are properly prototyped
        5. Do not include explanatory text outside of code comments

        BASE CODE TO MODIFY:
        {code}

        ADDITIONAL CONSTRAINTS:
        1. Maintain original functionality while ensuring x64 compatibility
        2. Use only Windows API functions that exist in modern Windows versions
        3. Include proper error handling
        4. Avoid deprecated functions
        5. Include security checks where appropriate
        """
        
        # Add debug logging
        print(f"Sending request to: {client.base_url}")
        
        completion = client.chat.completions.create(
            model="RichardErkhov/WhiteRabbitNeo_-_WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-gguf",
            messages=[
                {"role": "system", "content": "You are a Windows systems programming expert."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7
        )
        
        if not completion:
            print("No response received from AI server")
            return None
            
        return completion.choices[0].message.content
    except Exception as e:
        print(f"Error submitting to AI: {str(e)}")
        print(f"Error type: {type(e)}")  # Add error type for debugging
        return None

def generate_loader(selected_options, code_blocks, selected_replacements=None):
    """Generate a combined shellcode loader from selected techniques
    
    Args:
        selected_options: List of selected techniques
        code_blocks: Dictionary of available code blocks
        selected_replacements: List of specific function replacements to include
    """
    if not selected_options or not code_blocks:
        print("Error: No options selected or code blocks empty")
        return False
    
    # Get the mapping of general options to specific implementations
    available_snippets = get_available_snippets(code_blocks)
    
    # Create a mapping of selected options to their actual implementation names
    implementation_map = {}
    for category, techniques in available_snippets.items():
        for technique, implementations in techniques.items():
            if technique in selected_options:
                # For now, use the first available implementation
                if isinstance(implementations, list) and implementations:
                    implementation_map[technique] = implementations[0]
                else:
                    implementation_map[technique] = implementations

    # Check if Structs.h is available
    structs_header = code_blocks.get("Structs.h", "")
    
    # Create initial merged code with headers
    merged_code = """
#include <windows.h>
#include <stdio.h>

// Function replacements
"""
    # Only add specifically requested replacements
    if selected_replacements:
        for replacement in selected_replacements:
            if replacement in code_blocks:
                merged_code += f"\n// {replacement}\n"
                merged_code += code_blocks[replacement] + "\n"
            else:
                print(f"Warning: Requested replacement '{replacement}' not found in code blocks")

    # Add structs and rest of implementation
    merged_code += f"""
// Required structures and definitions
{structs_header}

// Combined shellcode loader using multiple techniques
"""
    
    # Submit each implementation to AI and use the returned code
    print("\nProcessing techniques through AI...")
    for option in selected_options:
        actual_implementation = implementation_map.get(option)
        if actual_implementation and actual_implementation in code_blocks:
            print(f"Processing {option}...")
            code = code_blocks[actual_implementation]
            processed_code = submit_to_ai(code, option)
            if processed_code:
                merged_code += f"\n// Implementation of {option}\n"
                merged_code += processed_code + "\n"
            else:
                print(f"Warning: AI processing failed for {option}")

    # Add main function
    merged_code += """
int main() {
    // Shellcode placeholder - replace with your encoded payload
    unsigned char shellcode[] = { 0x90, 0x90, 0x90 }; // Example NOP sled
    SIZE_T shellcode_size = sizeof(shellcode);
    
    // Initialize memory using replacement functions
    custom_memset(shellcode, 0x90, shellcode_size);  // Using replacement instead of memset
    
    // Execute combined techniques
"""
    
    # Add calls to each selected technique
    for option in selected_options:
        merged_code += f"    // Execute {option}\n"
    
    merged_code += """
    return 0;
}
"""

    # Write to a file
    with open("loader.c", "w") as file:
        file.write(merged_code)

def get_available_replacements():
    """Return a dictionary of available function replacements organized by category"""
    return {
        "Memory Management": {
            "Free": ["Free Function Replacement", "Free Function Replacement (2)"],
            "Malloc": ["Malloc Function Replacement", "Malloc Function Replacement 2"],
            "Realloc": ["Realloc Function Replacement", "Realloc Function Replacement (2)"],
            "Memory Operations": {
                "Memcmp": "Memcmp Function Replacement",
                "Memcpy": "Memcpy Function Replacement",
                "Memmove": "Memmove Function Replacement",
                "Memset": "Memset Function Replacement",
                "ZeroMemory": "ZeroMemory Function Replacement"
            }
        },
        "String Operations": {
            "ASCII": {
                "Basic": {
                    "Strcat": "Strcat Function Replacement",
                    "Strchr": "Strchr Function Replacement",
                    "Strcmp": "Strcmp Function Replacement",
                    "Strcpy": "Strcpy Function Replacement",
                    "Strlen": "Strlen Function Replacement"
                },
                "Extended": {
                    "Strcicmp": "Strcicmp Function Replacement",
                    "Strcspn": "Strcspn Function Replacement",
                    "Strdup": "Strdup Function Replacement",
                    "Stristr": "Stristr Function Replacement",
                    "Strncat": "Strncat Function Replacement",
                    "Strncpy": "Strncpy Function Replacement",
                    "Strrchr": "Strrchr Function Replacement",
                    "Strspn": "Strspn Function Replacement",
                    "Strstr": "Strstr Function Replacement",
                    "Strtok": "Strtok Function Replacement"
                },
                "Case Conversion": {
                    "Tolower": "Tolower Function Replacement",
                    "Toupper": "Toupper Function Replacement"
                }
            },
            "Wide Char": {
                "Basic": {
                    "Wcscat": "Wcscat Function Replacement",
                    "Wcschr": "Wcschr Function Replacement",
                    "Wcscmp": "Wcscmp Function Replacement",
                    "Wcscpy": "Wcscpy Function Replacement",
                    "Wcslen": "Wcslen Function Replacement"
                },
                "Extended": {
                    "Wcscspn": "Wcscspn Function Replacement",
                    "Wcsdup": "Wcsdup Function Replacement",
                    "Wcsicmp": "Wcsicmp Function Replacement",
                    "Wcsistr": "Wcsistr Function Replacement",
                    "Wcsncat": "Wcsncat Function Replacement",
                    "Wcsncpy": "Wcsncpy Function Replacement",
                    "Wcsrchr": "Wcsrchr Function Replacement",
                    "Wcsspn": "Wcsspn Function Replacement",
                    "Wcsstr": "Wcsstr Function Replacement",
                    "Wcstok": "Wcstok Function Replacement"
                }
            }
        },
        "Output": {
            "Printf": "Printf Function Replacement",
            "Wprintf": "Wprintf Function Replacement"
        }
    }

def list_available_replacements():
    """Print available function replacements in a hierarchical structure"""
    replacements = get_available_replacements()
    print("\nAvailable Function Replacements:")
    print("-" * 50)
    
    def print_nested_dict(d, indent=0):
        for key, value in d.items():
            print("  " * indent + f"- {key}")
            if isinstance(value, dict):
                print_nested_dict(value, indent + 1)
            elif isinstance(value, list):
                for item in value:
                    print("  " * (indent + 1) + f"- {item}")
            else:
                print("  " * (indent + 1) + f"- {value}")
    
    print_nested_dict(replacements)

# Path to markdown file containing code snippets
markdown_file = "code_snippets.md"

if __name__ == "__main__":
    # Parse the markdown and store the code blocks
    code_blocks = parse_markdown(markdown_file)
    
    # Show available options
    list_available_options()
    
    # Get user input for selected options
    print("\nEnter the techniques you want to use (one per line)")
    print("Press Enter twice when done:")
    
    selected_options = []
    while True:
        option = input().strip()
        if not option:  # Empty line
            break
        selected_options.append(option)
    
    # Show available replacements and get user input
    list_available_replacements()
    print("\nEnter the function replacements you want to include (one per line)")
    print("Press Enter twice when done:")
    
    selected_replacements = []
    while True:
        replacement = input().strip()
        if not replacement:  # Empty line
            break
        selected_replacements.append(replacement)
    
    if selected_options:
        print(f"\nSelected options: {selected_options}")
        print(f"Selected replacements: {selected_replacements}")
        generate_loader(selected_options, code_blocks, selected_replacements)
        print("\nLoader generated in loader.c")
    else:
        print("No options selected. Exiting.")

