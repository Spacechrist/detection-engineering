import tomllib   # Importing the tomllib module for working with TOML files
import sys       # Importing the sys module (for system-related functionality)
import os

##file = "alert_example.toml"  # Setting the variable 'file' to the name of the TOML file to be loaded
## Opening the TOML file in binary mode and assigning it to the variable 'toml'
##with open(file,"rb") as toml:
##    alert = tomllib.load(toml) # Loading the TOML data using the tomllib module

failure = 0

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root,file)
            with open(full_path,"rb") as toml: # Opening the TOML file in binary mode and assigning it to the variable 'toml'
                alert = tomllib.load(toml) # Loading the TOML data using the tomllib module

                present_fields = []  # Initializing an empty list called 'present_fields' to store fields found in the TOML file
                missing_fields = []  # Initializing an empty list called 'missing_fields' to store required fields that are missing

                try:
                    if alert['metadata']['creation_date']:
                        pass
                except:
                    print("The metadata table does not contain a creation_date on: " + full_path)
                    failure = 1

                # Checking the type of alert rule specified in the TOML file and setting the required fields accordingly
                if alert['rule']['type'] == "query": #Query Alert
                    required_fields = ['description','name','rule_id','risk_score','severity','type','query']
                elif alert['rule']['type'] == "eql": #event correlation alert (EQL)
                    required_fields = ['description','name','risk_score','severity','type','query','language']
                elif alert['rule']['type'] == "threshold": #threshold based alert
                    required_fields = ['description','name','risk_score','severity','type','query','threshold']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break
                # Iterating over the tables in the TOML data
                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                # Checking for missing required fields
                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)

                # Checking if there are any missing fields and printing the result
                if missing_fields:
                    print("The following fields do not exist in " + file + ": " + str(missing_fields))
                    failure = 1                
                else:
                    print("Validation Passed for: " + file)

if failure != 0:
    sys.exit(1)