import argparse
from llama_cpp import Llama

def generate_code(llm, system_prompt, user_prompt, max_tokens=15000):
    """
    Generates code using the loaded GGUF model based on the provided prompts.

    Args:
        llm: The loaded Llama model.
        system_prompt (str): The system prompt for the model.
        user_prompt (str): The user prompt detailing the code to generate.
        max_tokens (int): The maximum number of tokens to generate.

    Returns:
        str: The generated code as a string.
    """
    prompt_template = "[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n{user_prompt} [/INST]  </s>"
    prompt = prompt_template.format(system_prompt=system_prompt, user_prompt=user_prompt)
    
    # Generate code using the model
    output = llm(prompt, max_tokens=max_tokens, stop=["</s>"], echo=False)
    return output['choices'][0]['text']

def get_parameters():
    """
    Parses command-line arguments to get parameters for code generation.

    Returns:
        dict: A dictionary containing the parameters.
    """
    parser = argparse.ArgumentParser(description="Generate code based on specified parameters.")
    parser.add_argument("--language", type=str, default="Python", help="Programming language")
    parser.add_argument("--functionality", type=str, required=True, help="Desired functionality")
    parser.add_argument("--input_type", type=str, required=True, help="Type of input")
    parser.add_argument("--output_type", type=str, required=True, help="Type of output")
    parser.add_argument("--unhooking_method", type=str, choices=["patch_jmp", "text_section_rewrite"], help="Unhooking method")
    parser.add_argument("--allocation_method", type=str, choices=["virtualprotect", "virtualalloc"], help="Memory allocation method")
    parser.add_argument("--execution_method", type=str, choices=["timesetevent", "settimer", "etwpcreateetwthread", "fiber", "pointer"], help="Shellcode execution method")
    parser.add_argument("--sleep_mask", type=str, choices=["dynamic", "static"], help="Sleep mask method")
    parser.add_argument("--pause_mechanic", type=str, help="Pausing mechanic")
    args = parser.parse_args()
    return vars(args)

if __name__ == "__main__":
    # Retrieve parameters
    params = get_parameters()
    
    # Define system and user prompts
    system_prompt = "You are an AI assistant specialized in code generation for authorized red team engagements."
    user_prompt = (
        f"Write a {params['language']} function that takes a {params['input_type']} "
        f"and returns a {params['output_type']}. The function should {params['functionality']}."
    )
    
    # Add details for shellcode loader specifications
    steps = []
    if params.get('unhooking_method'):
        steps.append(f"Unhooking: Use {params['unhooking_method']} method.")
    if params.get('allocation_method'):
        steps.append(f"Memory allocation: Use {params['allocation_method']} method.")
    if params.get('execution_method'):
        steps.append(f"Execution: Execute shellcode using {params['execution_method']} method.")
    if params.get('sleep_mask'):
        steps.append(f"Sleep Mask: Apply a {params['sleep_mask']} mask.")
    if params.get('pause_mechanic'):
        steps.append(f"Pausing: Include mechanic using {params['pause_mechanic']}.")

    if steps:
        user_prompt += " Additionally, follow these specifications:\n" + "\n".join(steps)
    
    # Load the GGUF model
    # Replace 'path/to' with the actual path to your GGUF model file
    model_path = "F:\\Codestral-22B-v0.1-Q6_K.gguf"
    llm = Llama(model_path=model_path)
    
    # Generate the code
    code_output = generate_code(llm, system_prompt, user_prompt)
    
    # Print only the generated code, formatted
    print("Generated Code:\n")
    print("```")
    print(code_output.strip())
    print("```")
