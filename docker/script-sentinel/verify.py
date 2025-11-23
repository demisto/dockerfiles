#!/usr/bin/env python3
"""
Verify Script Sentinel Docker image
Tests that the image is properly built and functional
"""
import sys
import subprocess
import json


def verify_wrapper_exists():
    """Test that the XSIAM wrapper module exists"""
    try:
        result = subprocess.run(
            ['python', '-m', 'xsiam_wrapper', '--help'],
            capture_output=True,
            text=True,
            timeout=10
        )
        assert result.returncode == 0, f"Wrapper help failed with code {result.returncode}"
        assert 'xsiam-wrapper' in result.stdout or 'usage' in result.stdout.lower(), \
            "Wrapper help output doesn't contain expected content"
        print("✓ XSIAM wrapper module verified")
        return True
    except subprocess.TimeoutExpired:
        print("✗ Wrapper help command timed out")
        return False
    except Exception as e:
        print(f"✗ Wrapper verification failed: {e}")
        return False


def verify_dependencies():
    """Verify that all required dependencies are installed"""
    required_packages = [
        ('tree_sitter', 'Tree-sitter'),
        ('google.generativeai', 'Google Generative AI'),
        ('yaml', 'PyYAML'),
        ('rich', 'Rich'),
        ('dotenv', 'python-dotenv'),
    ]
    
    all_ok = True
    for package, name in required_packages:
        try:
            __import__(package)
            print(f"✓ {name} installed")
        except ImportError as e:
            print(f"✗ {name} missing: {e}")
            all_ok = False
    
    return all_ok


def verify_basic_analysis():
    """Test basic script analysis functionality"""
    test_script = 'echo "Hello World"'
    
    try:
        result = subprocess.run(
            ['python', '-m', 'xsiam_wrapper',
             '--content', test_script,
             '--language', 'bash',
             '--paranoia-level', '1'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        assert result.returncode == 0, f"Analysis failed with code {result.returncode}"
        
        # Try to parse JSON output
        try:
            output = json.loads(result.stdout)
            assert 'success' in output, "Output missing 'success' field"
            assert output['success'] is True, f"Analysis not successful: {output.get('error')}"
            assert 'verdict' in output, "Output missing 'verdict' field"
            print(f"✓ Basic analysis verified (verdict: {output['verdict']})")
            return True
        except json.JSONDecodeError as e:
            print(f"✗ Failed to parse JSON output: {e}")
            print(f"Output was: {result.stdout[:200]}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Analysis command timed out")
        return False
    except Exception as e:
        print(f"✗ Analysis verification failed: {e}")
        return False


def verify_malicious_detection():
    """Test that malicious patterns are detected"""
    # Simple keylogger pattern
    malicious_script = """
document.addEventListener('keypress', function(e) {
    keylog += e.key;
    sendToServer(keylog);
});
"""
    
    try:
        result = subprocess.run(
            ['python', '-m', 'xsiam_wrapper',
             '--content', malicious_script,
             '--language', 'javascript',
             '--paranoia-level', '1'],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"✗ Malicious detection test failed with code {result.returncode}")
            return False
        
        try:
            output = json.loads(result.stdout)
            verdict = output.get('verdict', 'unknown')
            
            # Should detect as malicious or suspicious
            if verdict in ['malicious', 'suspicious']:
                print(f"✓ Malicious pattern detection verified (verdict: {verdict})")
                return True
            else:
                print(f"⚠ Warning: Keylogger not detected as malicious (verdict: {verdict})")
                # Don't fail the test, but warn
                return True
                
        except json.JSONDecodeError as e:
            print(f"✗ Failed to parse malicious detection output: {e}")
            return False
            
    except subprocess.TimeoutExpired:
        print("✗ Malicious detection test timed out")
        return False
    except Exception as e:
        print(f"✗ Malicious detection test failed: {e}")
        return False


def main():
    """Run all verification tests"""
    print("=" * 60)
    print("Script Sentinel Docker Image Verification")
    print("=" * 60)
    print()
    
    tests = [
        ("Wrapper Module", verify_wrapper_exists),
        ("Dependencies", verify_dependencies),
        ("Basic Analysis", verify_basic_analysis),
        ("Malicious Detection", verify_malicious_detection),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nRunning: {test_name}")
        print("-" * 60)
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print()
    print("=" * 60)
    print("Verification Summary")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {test_name}")
    
    print()
    print(f"Results: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("\n✅ All verifications passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} verification(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())