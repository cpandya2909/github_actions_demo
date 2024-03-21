import requests
import os
from bs4 import BeautifulSoup
import pandas as pd

# variables
# Define repository owner and name
repo_owner = "cpandya2909"
repo_name = "github_actions_demo"

list_report = []

# Class for  Github session for API calls
class GithubSession():
    """GitHubSession Class to interact with GitHub APIs"""

    github_full_url = ''
    GSession = None

    def __init__(self,github_org:str = '', github_base_url: str = '') -> None:
        """Raises VauleError if Org URL or ORG is invalid"""

        if not isinstance(github_org,str) or github_org == '':
            raise ValueError
        
        if not isinstance(github_base_url,str):
            raise ValueError
        
        if github_base_url == '':
            github_base_url = "https://api.github.com/repos/"
        
        github_token = os.getenv('GITHUB_TOKEN','')

        if github_token == '':
            raise
        self.github_full_url = f"{github_base_url}{github_org}"
        # Set headers with authorization
        auth_headers = {"Authorization": f"token {github_token}"}

        session = requests.Session()
        session.headers = auth_headers
        self.GSession = session


    def getDependabotAlerts(self,repoName:str ='') -> list:
        """Return List[Alerts] from GitHub repo name, Return [] if error"""
    
        if not isinstance(repoName,str) or repoName == '':
            return []
        
        calling_url = f"{self.github_full_url}/{repoName}/dependabot/alerts"


        try:
        # Send GET request
            response = self.GSession.get(calling_url)

            # Check for successful response
            if response.status_code == 200:
                return response.json()
            else:
               return []
        except requests.exceptions.RequestException as error:
            print(repr(error))
            return []

def getLikelyhoodforCWE(cweID:str = '') -> str:
    """Call cwe.mitre.org and return likelyhood as str.
    Return '' if any error"""

    if (not isinstance(cweID,str)) or cweID == '':
        return ''

    cweID = cweID.upper()
    onlyid = cweID.strip('CWE-')
    try:
        intCWEId = int(onlyid)
    except Exception as e:
        return ''

    cwe_url = 'https://cwe.mitre.org/data/definitions/'
    response = requests.get(url=f"{cwe_url}{intCWEId}.html")
    if response.status_code == 200:

        soup = BeautifulSoup(response.content, "html.parser")

        Likelihood_Of_Exploit_element = soup.find(id='Likelihood_Of_Exploit')
        if Likelihood_Of_Exploit_element is None:
            return ''
        value = Likelihood_Of_Exploit_element.find(class_='indent').text
        if isinstance(value,str):
            return value
        else:
            return ''

    # clean up to always return valid return value
    return ''


# Start main logic
        
repo_name = 'vul_code'
githubSession = GithubSession(github_org='cpandya2909')


list_severityLevel_in_consideration = ['high']
list_likelihood_in_consideration = ['high']
dependabot_alerts = githubSession.getDependabotAlerts(repoName=repo_name)
for alerts in dependabot_alerts:
    if alerts['state'] != 'open':
        continue
    advisory = alerts['security_advisory']
    if advisory['severity'].lower() not in list_severityLevel_in_consideration:
        continue
    for cwe in advisory['cwes']:
            cwe_id = cwe['cwe_id']
            likelyhood = getLikelyhoodforCWE(cweID = cwe_id)
            if likelyhood == '':
                continue
            if likelyhood.lower() not in list_likelihood_in_consideration:
                continue
            list_object = {}
            list_object['Package name'] = alerts['dependency']['package']['name']
            list_object['Package type'] = alerts['dependency']['package']['ecosystem']
            list_object['CWE ID'] = cwe_id
            list_object['description'] = advisory['description']
            list_object['severity'] = advisory['severity']
            list_object['Likelihood'] = likelyhood
            list_report.append(list_object)
df = pd.DataFrame(list_report).to_excel("vul_report_excel.xlsx",index=None)
