# Importing necessary libraries
import requests  # for making HTTP requests
import tomllib   # assuming this is a custom library for handling TOML files
import os       # for interacting with the operating system
import sys      # for system-specific operations and functions

# URL of the JSON file to fetch
url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
# Headers for the HTTP request
headers = {
    'accept': 'application/json'
}

# Fetching and parsing JSON data from the specified URL
mitreData = requests.get(url, headers=headers).json()
# Dictionary to store mapped MITRE data
mitreMapped = {}
# Variable to track any failures
failure = 0

# Looping through objects in the MITRE data
for object in mitreData['objects']:
    tactics = []
    # Checking if the object is of type 'attack-pattern'
    if object['type'] == 'attack-pattern':
        # Checking if there are external references
        if 'external_references' in object:
            for reference in object['external_references']:
                # Checking if there is an external ID that starts with "T"
                if 'external_id' in reference:
                    if ((reference['external_id'].startswith("T"))):
                        # Checking if there are associated kill chain phases
                        if 'kill_chain_phases' in object:
                            for tactic in object['kill_chain_phases']:
                                tactics.append(tactic['phase_name'])
                        # Extracting relevant information
                        technique = reference['external_id']
                        name = object['name']
                        url = reference['url']

                        # Checking if the object is deprecated
                        if 'x_mitre_deprecated' in object:
                            deprecated = object['x_mitre_deprecated']
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': deprecated}
                            mitreMapped[technique] = filtered_object
                        else:
                            filtered_object = {'tactics': str(tactics), 'technique': technique, 'name': name, 'url': url, 'deprecated': "False"}
                            mitreMapped[technique] = filtered_object

# Dictionary to store alert data
alert_data = {}
# Walking through files in a specified directory
for root, dirs, files in os.walk(r"C:\Users\Spacechrist\Documents\GitHub\TCMDetectionEngineering\converted-detections"):
    for file in files:
        # Checking if the file has a .toml extension
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            # Opening and parsing the TOML file
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                filtered_object_array = []

                # Checking if the alert's framework is "MITRE ATT&CK"
                if alert['rule']['threat'][0]['framework'] == "MITRE ATT&CK":
                    for threat in alert['rule']['threat']:
                        technique_id = threat['technique'][0]['id']
                        technique_name = threat['technique'][0]['name']

                        # Checking if there's a specified tactic
                        if 'tactic' in threat:
                            tactic = threat['tactic']['name']
                        else:
                            tactic = "none"
                        # Checking if there's a subtechnique
                        if 'subtechnique' in threat['technique'][0]:
                            subtechnique_id = threat['technique'][0]['subtechnique'][0]['id']
                            subtechnique_name = threat['technique'][0]['subtechnique'][0]['name']
                        else:
                            subtechnique_id = "none"
                            subtechnique_name = "none"

                        # Creating a filtered object and appending to the array
                        filtered_object = {'tactic': tactic, 'technique_id': technique_id, "technique_name": technique_name, "subtechnique_id": subtechnique_id, "subtechnique_name": subtechnique_name}
                        filtered_object_array.append(filtered_object)
                        alert_data[file] = filtered_object_array

# List of MITRE tactics
mitre_tactic_list = ['none','reconnaissance','resource development','initial access','execution','persistence','privilege escalation','defense evasion','credential access','discovery','lateral movement','collection','command and control','exfiltration','impact']

# Loop through each file in alert_data
for file in alert_data:
    for line in alert_data[file]:
        tactic=line['tactic'].lower()
        technique_id=line['technique_id']
        subtechnique_id=line['subtechnique_id']

        # Check to ensure MITRE Tactic exists
        if tactic not in mitre_tactic_list:
            print("The MITRE Tactic supplied does not exist: " + "\"" + tactic + "\"" + " in " + file)
            failure = 1
       # Check to make sure the MITRE Technique ID is valid
        try:
            if mitreMapped[technique_id]:
                pass
        except KeyError:
            print("Invalid MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
            failure = 1
       # Check to see if the MITRE TID + Name combination is Valid
        try:
            mitre_name = mitreMapped[technique_id]['name']
            alert_name = line['technique_name']
            if alert_name != mitre_name:
                print("MITRE Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                failure = 1
        except KeyError:
            pass

       # Check to see if the subTID + Name Entry is Valid
        try:
            if subtechnique_id != "none":
                mitre_name = mitreMapped[subtechnique_id]['name']
                alert_name = line['subtechnique_name']
                if alert_name != mitre_name:
                    print("MITRE Sub-Technique ID and Name Mismatch in " + file + " EXPECTED: " + "\"" + mitre_name + "\"" + " GIVEN: " + "\"" + alert_name + "\"")
                    failure = 1
        except KeyError:
            pass

       # Check to see if the technique is deprecated
        try:
            if mitreMapped[technique_id]['deprecated'] == True:
                 print("Deprecated MITRE Technique ID: " + "\"" + technique_id + "\"" + " in " + file)
                 failure = 1
        except KeyError:
            pass

# If there were any failures, exit the script with an error code
if failure != 0:
    sys.exit(1)
