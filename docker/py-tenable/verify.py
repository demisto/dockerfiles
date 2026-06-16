import sys
# Import the packages you added to your Pipfile to make sure they load
import requests 

print("Sanity check passed: Dependencies loaded successfully inside the container!")
sys.exit(0) # 0 tells the automated pipeline that everything works perfectly