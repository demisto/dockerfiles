#######################
# Description: CrowdStrike Falcon Query Login Script for XSOAR
# Author: Griffin Refol
# Creation: June 2024
#######################
from falconpy import APIHarnessV2
import csv
import urllib3
import io

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

######################
# Description: Test connection to CrowdStrike Falcon API
# Parameters: None
# Returns: Success or Failure message to Demisto
######################
def test_connection():
    try:
        auth = APIHarnessV2(client_id="8ecd3a7fff9841458b66a4d816a76380",client_secret="2TQ6zlEdH4yj0Cx7YX195FgMveLiwauVUB8KnJf3")
        response = auth.command("GetSensorInstallersByQuery", limit=1)
    except ValueError:
        return 'Connection Error: The URL or The API key you entered is probably incorrect, please try again.'
    return auth

####################
# Description: This function is designed to query crowdstrike logins based on a hostname filter (see https://falconpy.io/Service-Collections/Discover.html#query_logins for documentation)
# Params: Hostname, authentication object
# Return: list of login ids 
# Example: ['0a5b1b6c97734ff7801837c1d1070336_b866f5e6412630ef8bc6d05cce8f5b94', '0a5b1b6c97734ff7801837c1d1070336_a91119119f533d648ebac83350b7f0a8', '0a5b1b6c97734ff7801837c1d1070336_980fc16ba0ce356e97311915716dbbfe', '0a5b1b6c97734ff7801837c1d1070336_972ec7560ee43f03b00deadf0682e1c0']
####################

def QueryLogins(hostname, auth):
    
    response = auth.command(action="query_logins", 
                            limit=10,
                            filter=f"hostname:'{hostname}'", 
                            sort="login_timestamp|desc")

    if response['body']['meta']['pagination']['total'] >0:
        return response['body']['resources']
    

####################
# Description: looks up login ids given by QueryLogins into human-readable information (see https://falconpy.io/Service-Collections/Discover.html#get_logins)
# # Params: List of login ids, authentication object
# Return: csv of login information
# Example: 
#   Username,Login Type,Login Status,Login Domain,Login Timestamp,Local Administrator?,Host Country,Host City
#   h4qv30,Interactive,Successful,LINDE.LDS.GRP,2024-06-04T15:00:00Z,No,United States of America,New York City
####################

def GetLogins(IDList, auth):
    response = auth.command(action="get_logins", 
                            ids=IDList)
    # Initialize structure for creating CSV
    columns = ["Username", "Login Type", "Login Status", "Login Domain", "Login Timestamp", "Local Administrator?", "Host Country", "Host City"]
    rows = []
    
    for login in response['body']['resources']:
        row = {
            "Username": login.get("username", ""),
            "Login Type": login.get("login_type", ""),
            "Login Status": login.get("login_status", ""),
            "Login Domain": login.get("login_domain", ""),
            "Login Timestamp": login.get("login_timestamp", ""),
            "Local Administrator?": login.get("admin_privileges", ""),
            "Host Country": login.get("host_country", ""),
            "Host City": login.get("host_city", "")
        }
        # Check if the row contains any non-empty values
        if any(row.values()):
            rows.append(row)
    
    # Write CSV data in memory. Read https://docs.python.org/3/library/io.html if you have no idea what this is
    csv_buffer = io.StringIO(newline="")
    writer = csv.DictWriter(csv_buffer, fieldnames=columns)
    writer.writeheader()
    writer.writerows(rows)
    
    # Get the data from CSV in memory
    csv_text = csv_buffer.getvalue()
    
    return csv_text
######################
# Description: Main function
# Parameters: None
# Returns: Success or Failure message to console
######################
def main():
    authentication = test_connection()
    IDList = QueryLogins("WLGNAOL32ee7",authentication)
    print(IDList)
    print(GetLogins(IDList, authentication))
    
if __name__ in ('__main__', 'builtin', 'builtins'):
    main()