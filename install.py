#!/usr/bin/env python3
"""VIPER 2.0 — One-click installer and setup wizard."""
import subprocess, sys, os, shutil, json


def main():
    print("=" * 50)
    print("VIPER 2.0 — Setup Wizard")
    print("=" * 50)

    # Step 1: Install Python dependencies
    print("\n[1/4] Installing Python dependencies...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt", "-q"])

    # Step 2: Check for optional tools
    print("\n[2/4] Checking optional tools...")
    tools = {
        "nuclei": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "subfinder": "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "httpx": "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    }
    for tool, install_cmd in tools.items():
        if shutil.which(tool):
            print(f"  [OK] {tool}")
        else:
            print(f"  [--] {tool} not found (optional: {install_cmd})")

    # Step 3: Configure LLM
    print("\n[3/4] LLM Configuration...")
    print("  Choose your LLM backend:")
    print("  1. API Key (OpenAI, Anthropic, DeepSeek)")
    print("  2. Ollama (free, local)")
    print("  3. Skip (configure later via .env)")

    choice = input("  Choice [1/2/3]: ").strip()

    env_lines = []
    if choice == "1":
        provider = input("  Provider [openai/anthropic/deepseek]: ").strip().lower()
        api_key = input(f"  {provider.upper()} API Key: ").strip()
        if provider == "openai":
            env_lines.append(f"OPENAI_API_KEY={api_key}")
            env_lines.append("VIPER_MODEL=openai/gpt-4o")
        elif provider == "anthropic":
            env_lines.append(f"ANTHROPIC_API_KEY={api_key}")
            env_lines.append("VIPER_MODEL=anthropic/claude-sonnet-4-20250514")
        elif provider == "deepseek":
            env_lines.append(f"DEEPSEEK_API_KEY={api_key}")
            env_lines.append("VIPER_MODEL=deepseek/deepseek-chat")
        env_lines.append("VIPER_USE_CLI=false")
    elif choice == "2":
        model = input("  Ollama model name [deepseek-r1:14b]: ").strip() or "deepseek-r1:14b"
        env_lines.append(f"VIPER_MODEL=ollama/{model}")
        env_lines.append("VIPER_USE_CLI=false")
        print(f"  Make sure Ollama is running: ollama serve")
        print(f"  And model is pulled: ollama pull {model}")

    # Step 4: Write .env
    if env_lines:
        env_lines.insert(0, "# VIPER 2.0 Configuration")
        env_lines.append("VIPER_MAX_TOKENS=1024")
        env_lines.append("VIPER_TEMPERATURE=0.3")
        env_lines.append("VIPER_RATE_LIMIT=30")
        with open(".env", "w") as f:
            f.write("\n".join(env_lines) + "\n")
        print("\n  [OK] Config saved to .env")

    # Create directories
    for d in ["data", "logs", "reports", "reports/pocs", "models", "knowledge"]:
        os.makedirs(d, exist_ok=True)

    print("\n[4/4] Setup complete!")
    print("\n" + "=" * 50)
    print("Quick Start:")
    print("  python viper.py https://target.com          # Quick scan")
    print("  python viper.py https://target.com --full    # Full hunt")
    print("  python viper.py --help                       # All options")
    print("=" * 50)


if __name__ == "__main__":
    main()
