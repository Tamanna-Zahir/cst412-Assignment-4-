# main python file 
import os
import matplotlib.pyplot as plt

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
def check_request(sub_id, res_id, action):
    """
    Checks if a request is permitted or denied based on ABAC rules.

    Args:
        sub_id (str): Subject ID making the request.
        res_id (str): Resource ID being accessed.
        action (str): Action being performed.

    Returns:
        str: "Permit" if the request is allowed, otherwise "Deny".
    """
    for rule in abac_policy["rules"]:
        # print("rabac_policy[rules]", rule)
        # Check subject condition
        if rule["subCond"]:
            subject = next((user for user in abac_policy["users"] if user["uid"] == sub_id), None)
            if not subject or not evaluate_condition(rule["subCond"], subject):
                continue

        # Check resource condition
        if rule["resCond"]:
            resource = next((res for res in abac_policy["resources"] if res["rid"] == res_id), None)
            if not resource or not evaluate_condition(rule["resCond"], resource):
                continue

        # Check action
        if rule["acts"] and action not in rule["acts"]:
            continue

        # Check constraints
        if rule["cons"] and not evaluate_condition(rule["cons"], {"action": action, "subject": sub_id, "resource": res_id}):
            continue

        # If all conditions pass, permit the request
        return "Permit"

    # If no rule permits the request, deny it
    return "Deny"


def evaluate_condition(conditions, attributes):
    """
    Evaluates a set of conditions against a given set of attributes.

    Args:
        conditions (dict): Conditions to evaluate.
        attributes (dict): Attributes to check against.

    Returns:
        bool: True if all conditions are met, otherwise False.
    """
    if not conditions: 
        return True
    
    for key, value in conditions.items():
        if key not in attributes:
            return False

        attr_value = attributes[key]

        if isinstance(value, set):  # "in" operator
            if attr_value not in value:
                return False
        else:  # "equals" or other simple comparisons
            if attr_value != value:
                return False

    return True

def load_requests():
    """
    Prompts the user for a file path and loads requests from the specified file.

    Returns:
        list: List of parsed requests as tuples (sub_id, res_id, action).
    """
    file_path = input("Enter the file path to load the requests file: ")
    print()  # Add a blank line for better formatting

    requests = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                # Skip empty lines or comments
                if not line or line.startswith("#"):
                    continue

                # Parse the request as a tuple (subject_id, resource_id, action)
                parts = line.split(",")
                if len(parts) == 3:  # Ensure proper formatting
                    sub_id = parts[0].strip()
                    res_id = parts[1].strip()
                    action = parts[2].strip()

                    # Check if resource_id has multiple parts and split them correctly
                    if 'car' in res_id:
                        res_id = "car" + res_id.split("car")[1]

                    requests.append((sub_id, res_id, action))
                else:
                    print(f"Invalid request format: {line}")

    except FileNotFoundError:
        print("File not found. Please try again.")
    # print("test" ,  requests)

    return requests


def process_requests(file_path):
    """
    Processes a batch of requests and prints the result for each.

    Args:
        file_path (str): Path to the requests file.
    """
    requests = load_requests(file_path)
    for sub_id, res_id, action in requests:
        result = check_request(sub_id, res_id, action)
        print(f"Request: Subject={sub_id}, Resource={res_id}, Action={action} -> {result}")




#TODO: Framework Feature 4: Policy Coverage Analysis

#TODO: Framework Feature 5: Analyze Resource Access Patterns

def analyze_access_patterns():
    """
    Analyzes resource access patterns to identify the top 10 resources
    with the highest and lowest number of subjects granted permissions.
    Generates bar graphs for visualization.
    """
    
    # Dictionary to track the number of subjects accessing each resource
    access_count = {}


    # Loop through all rules to find which users can access which resources
    for rule in abac_policy["rules"]:
        # Match users based on rule's subject condition
        matched_users = [
            user
            for user in abac_policy["users"]
            if rule["subCond"] is None or evaluate_condition(rule["subCond"], user)
        ]
        # Match resources based on rule's resource condition
        matched_resources = [
            res
            for res in abac_policy["resources"]
            if rule["resCond"] is None or evaluate_condition(rule["resCond"], res)
        ]


        # Count the number of users who can access each resource
        for res in matched_resources:
            if res["rid"] not in access_count:
                access_count[res["rid"]] = 0
            access_count[res["rid"]] += len(matched_users)


    # Sort resources by access count
    sorted_resources = sorted(access_count.items(), key=lambda x: x[1], reverse=True)

    # Top 10 most accessible resources
    top_10_most_accessible = sorted_resources[:10]
    resources_most, counts_most = zip(*top_10_most_accessible) if top_10_most_accessible else ([], [])

    # Top 10 least accessible resources
    top_10_least_accessible = sorted_resources[-10:]
    resources_least, counts_least = zip(*top_10_least_accessible) if top_10_least_accessible else ([], [])

    # Bar graph for most accessible resources
    plt.figure(figsize=(10, 5))
    plt.bar(resources_most, counts_most)
    plt.title("Top 10 Most Accessible Resources")
    plt.xlabel("Resources")
    plt.ylabel("Number of Subjects")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()

    # Bar graph for least accessible resources
    plt.figure(figsize=(10, 5))
    plt.bar(resources_least, counts_least)
    plt.title("Top 10 Least Accessible Resources")
    plt.xlabel("Resources")
    plt.ylabel("Number of Subjects")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.show()


        
def main():

    load_abac_files()

    analyze_access_patterns()  
    

    # test_parsing()
    requests = load_requests()
    if requests:
            for request in requests:
                sub_id, res_id, action = request
                result = check_request(sub_id, res_id, action)
                print(f"Request: {request} => {result}")   
    pass
# -------------------------------------------------


if __name__ == "__main__":
    main()
# -------------------------------------------------