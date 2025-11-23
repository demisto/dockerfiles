#!/usr/bin/env python3
"""
Verification script to test that the demisto-sdk Docker container is working properly.
This script verifies various components installed in the container.
"""

import subprocess
import sys
import json
from pathlib import Path
from demisto_sdk.commands.common.hook_validations.readme import ReadMeValidator, mdx_server_is_up


def run_command(cmd, check=True):
    """Run a shell command and return the result."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=check)
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.CalledProcessError as e:
        return e.stdout.strip(), e.stderr.strip(), e.returncode


def verify_python_installation():
    """Verify Python and demisto-sdk installation."""
    print("🔍 Verifying Python and demisto-sdk installation...")
    
    # Check Python version
    stdout, stderr, code = run_command("python3 --version")
    if code == 0:
        print(f"✅ Python: {stdout}")
    else:
        print(f"❌ Python check failed: {stderr}")
        return False
    
    # Check demisto-sdk installation and version
    stdout, stderr, code = run_command("demisto-sdk --version")
    if code == 0:
        print(f"✅ demisto-sdk: {stdout}")
    else:
        print(f"❌ demisto-sdk check failed: {stderr}")
        return False
    
    return True


def verify_node_installation():
    """Verify Node.js and npm installation."""
    print("\n🔍 Verifying Node.js and npm installation...")
    
    # Check Node.js version
    stdout, stderr, code = run_command("node --version")
    if code == 0:
        print(f"✅ Node.js: {stdout}")
    else:
        print(f"❌ Node.js check failed: {stderr}")
        return False
    
    # Check npm version
    stdout, stderr, code = run_command("npm --version")
    if code == 0:
        print(f"✅ npm: {stdout}")
    else:
        print(f"❌ npm check failed: {stderr}")
        return False
    
    # Check jsdoc-to-markdown installation
    stdout, stderr, code = run_command("jsdoc2md --version", check=False)
    if code == 0:
        print(f"✅ jsdoc-to-markdown: {stdout}")
    else:
        print(f"⚠️  jsdoc-to-markdown check failed: {stderr}")
    
    return True


def verify_docker_cli():
    """Verify Docker CLI installation."""
    print("\n🔍 Verifying Docker CLI installation...")
    
    stdout, stderr, code = run_command("docker --version")
    if code == 0:
        print(f"✅ Docker CLI: {stdout}")
        return True
    else:
        print(f"❌ Docker CLI check failed: {stderr}")
        return False

def verify_jsdoc2md():
    """Verify jsdoc2md installation."""
    print("\n🔍 Verifying jsdoc2md installation...")
    
    stdout, stderr, code = run_command("jsdoc2md --version")
    if code == 0:
        print(f"✅ jsdoc2md: {stdout}")
        return True
    else:
        print(f"❌ jsdoc2md check failed: {stderr}")
        return False

def verify_mdx_server():
    """Verify MDX server functionality."""
    print("\n🔍 Verifying MDX server functionality...")
    
    try:
        with ReadMeValidator.start_mdx_server():
            if mdx_server_is_up():
                print("✅ MDX server started successfully")
                return True
            else:
                print("❌ MDX server failed to start properly")
                return False
    except Exception as e:
        print(f"❌ MDX server verification failed: {e}")
        return False


def main():
    """Run all verification checks."""
    print("🚀 Starting demisto-sdk Docker container verification...\n")
    
    checks = [
        ("Python & demisto-sdk", verify_python_installation),
        ("Node.js & npm", verify_node_installation),
        ("Docker CLI", verify_docker_cli),
        ("MDX server", verify_mdx_server),
    ]
    
    results = []
    for check_name, check_func in checks:
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"❌ {check_name} verification failed with exception: {e}")
            results.append((check_name, False))
    
    passed = 0
    total = len(results)
    
    for check_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {check_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Results: {passed}/{total} checks passed")
    
    if passed == total:
        print("🎉 All verifications passed! Container is ready to use.")
        sys.exit(0)
    else:
        print("⚠️  Some verifications failed. Please check the issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
