import sys
import logging
from tenable.tenableone import TenableOne

# Set up clean logging output for the XSOAR build pipeline
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("XSOAR-Verify")

logger.info("Initializing Docker image dependency verification...")

try:
    # 1. Test Core XSOAR Base Libraries
    import requests
    import urllib3
    import dateparser
    import tldextract
    logger.info("Success: Core XSOAR baseline libraries (requests, urllib3, dateparser, tldextract) loaded.")

    # 2. Test pyTenable Installation
    # Note: The pip package is 'pyTenable', but the python import namespace is 'tenable'
    import tenable
    from tenable.io import TenableIO
    
    # Try to extract the version to verify the library is fully active
    pytenable_version = getattr(tenable, '__version__', 'Unknown')
    logger.info(f"Success: pyTenable library loaded successfully (Detected Version: {pytenable_version}).")

    # 3. Finalization
    logger.info("Validation complete. All custom and baseline packages are present.")
    print("SUCCESS: Container environment is stable and ready for XSOAR integration distribution.")
    sys.exit(0)

except ImportError as error:
    logger.error(f"CRITICAL: Verification failed due to a missing or broken dependency.")
    logger.error(f"Error Details: {error}")
    sys.exit(1)
except Exception as unexpected_error:
    logger.error(f"CRITICAL: An unexpected runtime error occurred: {unexpected_error}")
    sys.exit(1)