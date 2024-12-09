# main python file 
import os

#Framework Feature 1: Data Structure:
abac_policy = {
    "users": [],
    "resources": [],
    "rules": []
}
# -------------------------------------------------

#Framework Feature 2: Parse ABAC Policies From Input Files:
#Prompts the user for the file path of the ABAC policy file.
#Reads the file line by line and parses the info based on the type
def load_abac_files(): 
    file_path = input("Enter the file path to load the ABAC policy file: ")
    print()

    try:
        with open(file_path, "r") as file:
            for line in file:
                #Remove leading and trailing whitespace
                line = line.strip()

                #Skip empty lines/comments
                if not line or line.startswith("#"):
                    continue

                if line.startswith("userAttrib"):
                    parse_user_attrib(line)
                elif line.startswith("resourceAttrib"):
                    parse_resource_attrib(line)
                elif line.startswith("rule"):
                    parse_rule(line)

    except FileNotFoundError:
        print ("File not found. Please try again.")
# -------------------------------------------------

#Parses a userAttrib line to extract the user ID and their attributes
def parse_user_attrib(line):
    #Extract the string inside the parentheses
    attribute_list = line[line.find("(") + 1 : line.rfind(")")]
    attributes = attribute_list.split(", ") #Split by comma and space

    #Initialize dictionary with the user ID
    user = {"uid": attributes[0]}

    #Parse remaining attributes and add them to the user dictionary
    for attr in attributes[1:]:
        key, value = attr.split("=")
        user[key] = parse_value(value)

    #Add the user to abac_policy
    if user not in abac_policy["users"]:
        abac_policy["users"].append(user)
# -------------------------------------------------

#Parses a resourceAttrib line to extract the resource ID and their attributes
def parse_resource_attrib(line):
    #Extract the string inside the parentheses
    attribute_list = line[line.find("(") + 1 : line.rfind(")")]
    attributes = attribute_list.split(", ")

    #Initialize dictionary with the resource ID
    resource = {"rid": attributes[0]}

    #Parse remaining attributes and add them to the resource dictionary
    for attr in attributes[1:]:
        key, value = attr.split("=")
        resource[key] = parse_value(value)

    #Add the resource to abac_policy
    if resource not in abac_policy["resources"]:
        abac_policy["resources"].append(resource)
# -------------------------------------------------

#Parses a rule line to extract its attributes
def parse_rule(line):
    #Extract the string inside the parentheses
    attribute_list = line[line.find("(") + 1 : line.rfind(")")]
    attribute = attribute_list.split(";")

    #Initialize dictionary to store rule attributes
    rule = {}

    #Parse subCond if it exists
    if attribute[0].strip():
        rule["subCond"] = parse_condition(attribute[0].strip())
    else:
        rule["subCond"] = None

    #Parse resCond if it exists
    if attribute[1].strip():
        rule["resCond"] = parse_condition(attribute[1].strip())
    else:
        rule["resCond"] = None

    #Parse acts if it exists
    if len(attribute) > 2 and attribute[2].strip():
        rule["acts"] = parse_value(attribute[2].strip())
    else:
        rule["acts"] = None

    #Parse cons if it exists
    if len(attribute) > 3 and attribute[3].strip():
        rule["cons"] = parse_condition(attribute[3].strip())
    else:
        rule["cons"] = None

    #Add the rule to abac_policy
    if rule not in abac_policy["rules"]:
        abac_policy["rules"].append(rule)  
# -------------------------------------------------
        
#Parses a value to determine if it's a set or an atomic value
def parse_value (value):
    if value.startswith("{") and value.endswith("}"):
        #Removes brackets and splits information by spaces to create a set
        return set(value[1:-1].split())
    #Return as-is for atomic values
    return value
# -------------------------------------------------

#Parses a condition string into a dictionary of conditions.
def parse_condition(condition):
    if not condition:
        return None
    
    #Initialize dictionary to store parsed conditions
    conditions = {}

    for cond in condition.split(","):
        if "[" in cond: #"[" denotes the "in" operator
            key, values = cond.split("[")
            conditions[key.strip()] = parse_value(values.strip(" ]"))
        elif "]" in cond: #"]" denotes the "contains" operator
            key, value = cond.split("]")
            conditions[key.strip()] = value.strip()
    return conditions
# -------------------------------------------------

#**Testing purposes to make sure parsing works correctly**
# def test_parsing():
#     load_abac_files()
    
#     print("Users:")
#     for user in abac_policy["users"]:
#         print(user)
#     print("\nResources:")
#     for resource in abac_policy["resources"]:
#         print(resource)
#     print("\nRules:")
#     for rule in abac_policy["rules"]:
#         print(rule)
# -------------------------------------------------

#TODO: Framework Feature 3: Check Requests

#TODO: Framework Feature 4: Policy Coverage Analysis

#TODO: Framework Feature 5: Analyze Resource Access Patterns
        
def main():
    #load_abac_files()
    #test_parsing()
    pass
# -------------------------------------------------

if __name__ == "__main__":
    main()
# -------------------------------------------------