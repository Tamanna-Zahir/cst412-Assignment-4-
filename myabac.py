# main python file 
import os
import matplotlib.pyplot as plt
import numpy as np
import sys


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
    """
    Loads the ABAC policy file based on command-line arguments for different modes.
    Supports -e, -a, and -b options as specified in the requirements.
    """
    
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python3 myabac.py -e <policy_file> <requests_file>")
        print("  python3 myabac.py -a <policy_file>")
        print("  python3 myabac.py -b <policy_file>")
        return
    option = sys.argv[1]
    policy_file = sys.argv[2]
    try:
        with open(policy_file, "r") as file:
            for line in file:
                # Remove leading and trailing whitespace
                line = line.strip()
                # Skip empty lines/comments
                if not line or line.startswith("#"):
                    continue
                if line.startswith("userAttrib"):
                    parse_user_attrib(line)
                elif line.startswith("resourceAttrib"):
                    parse_resource_attrib(line)
                elif line.startswith("rule"):
                    parse_rule(line)
        print(f"Loaded policy from {policy_file}.")
        if option == "-e":
            if len(sys.argv) < 4:
                print("Error: -e option requires a requests file.")
                return
            requests_file = sys.argv[3]
            requests = load_requests(requests_file)
            for request in requests:
                sub_id, res_id, action = request
                result = check_request(sub_id, res_id, action)
                print(f"Request: {request} => {result}")
        elif option == "-a":
            analyze_policy_coverage()
        elif option == "-b":
            analyze_access_patterns()
        else:
            print(f"Error: Unknown option {option}")
    except FileNotFoundError:
        print(f"Error: Policy file '{policy_file}' not found.")
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

# #Parses a rule line to extract its attributes
# def parse_rule(line):
#     #Extract the string inside the parentheses
#     attribute_list = line[line.find("(") + 1 : line.rfind(")")]
#     attribute = attribute_list.split(";")

#     #Initialize dictionary to store rule attributes
#     rule = {}

#     #Parse subCond if it exists
#     if attribute[0].strip():
#         rule["subCond"] = parse_condition(attribute[0].strip())
#     else:
#         rule["subCond"] = None

#     #Parse resCond if it exists
#     if attribute[1].strip():
#         rule["resCond"] = parse_condition(attribute[1].strip())
#     else:
#         rule["resCond"] = None

#     #Parse acts if it exists
#     if len(attribute) > 2 and attribute[2].strip():
#         rule["acts"] = parse_value(attribute[2].strip())
#     else:
#         rule["acts"] = None

#     #Parse cons if it exists
#     if len(attribute) > 3 and attribute[3].strip():
#         rule["cons"] = parse_condition(attribute[3].strip())
#     else:
#         rule["cons"] = None

#     #Add the rule to abac_policy
#     if rule not in abac_policy["rules"]:
#         abac_policy["rules"].append(rule)  
# -------------------------------------------------#Parses a rule line to extract its attributes
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
        rule["cons"] = parse_constraints(attribute[3].strip())
    else:
        rule["cons"] = None

    #Add the rule to abac_policy
    if rule not in abac_policy["rules"]:
        abac_policy["rules"].append(rule)  
# -------------------------------------------------
        
#Parses constraints from the rules and stores them in the required format
def parse_constraints(constraints):
    if not constraints:
        return None
    
    parsed_constraints = []

    #Map operators to their descriptons
    operator = {
        "=": "equals",
        ">": "subset",
        "[": "in",
        "]": "contains"
    }

    for constraint in constraints.split(","):
        constraint = constraint.strip()
        if "=" in constraint:
            sub_att, res_att = constraint.split("=")
            parsed_constraints.append({
                "sub_att": sub_att.strip(),
                "operator": operator["="],
                "res_att":res_att.strip()
            })
        elif ">" in constraint:
            sub_att, res_att = constraint.split(">")
            parsed_constraints.append({
                "sub_att": sub_att.strip(),
                "operator": operator[">"],
                "res_att":res_att.strip()
            })
        elif "[" in constraint:
            sub_att, res_att = constraint.split("[")
            parsed_constraints.append({
                "sub_att": sub_att.strip(),
                "operator": operator["["],
                "res_att":res_att.strip()
            })
        elif "]" in constraint:
            sub_att, res_att = constraint.split("]")
            parsed_constraints.append({
                "sub_att": sub_att.strip(),
                "operator": operator["]"],
                "res_att":res_att.strip()
            })
    return parsed_constraints

# ------------------------------------------------- hardcode rules 



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
def test_parsing():
    load_abac_files()
    # add_hardcoded_rules()

    print("Users:")
    for user in abac_policy["users"]:
        print(user)
    print("\nResources:")
    for resource in abac_policy["resources"]:
        print(resource)
    print("\nRules:")
    for rule in abac_policy["rules"]:
        print(rule)
# -------------------------------------------------





#TODO: Framework Feature 3: Check Requests



def evaluate_condition(conditions, attributes):
    """
    Evaluates a set of conditions against a given set of attributes.

    Args:
        conditions (dict): Conditions to evaluate.
        attributes (dict): Attributes to check against.

    Returns:
        bool: True if all conditions are met, otherwise False.
    """
    for key, value in conditions.items():
        if key not in attributes:
            return False

        attr_value = attributes[key]

        if isinstance(value, set):  # "in" operator
            if attr_value not in value:
                return False
        elif "contains" in key:  # "contains" operator
            if not (set(attr_value) & value):
                return False
        elif "supersetq" in key:  # "supersetq" operator
            if not value.issubset(attr_value):
                return False
        elif attr_value != value:  # "equals" operator
            return False

    return True 

def load_requests(file):
    """
    Prompts the user for a file path and loads requests from the specified file.

    Returns:
        list: List of parsed requests as tuples (sub_id, res_id, action).
    """

    file_path = file
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
                    requests.append((sub_id, res_id, action))
                else:
                    print(f"Invalid request format: {line}")

    except FileNotFoundError:
        print("File not found. Please try again.")

    # Return the parsed requests
    return requests

def find_subject(sub_id):
    """Fetch the subject based on the subject ID."""
    for user in abac_policy["users"]:
        if user["uid"] == sub_id:
            # print(f"Found matching user: {user}")
            return user
    return None

def find_resource(res_id):
    """Fetch the resource based on the resource ID."""
    for res in abac_policy["resources"]:
        if res["rid"] == res_id:
            # print(f"Found matching resource: {res}")
            return res
    return None

def evaluate_subject_condition(subject, subCond):
    if subCond is None:  # Handle the case where subCond is None
        return True  # or handle according to your logic (e.g., return False if not allowed)

    for attr, values in subCond.items():
        if subject.get(attr) not in values:
            return False
    return True

def evaluate_resource_condition(resource, res_cond):
    for attr, values in res_cond.items():
        if attr in resource:
            if resource[attr] not in values:
                return False  # If the attribute value doesn't match, return False
        else:
            return False  # If the attribute is not present, return False
    return True
def evaluate_action(acts, action):
    """Check if action is allowed based on the acts condition."""
    return action in acts  # Check if action is in the set of allowed actions


def evaluate_constraints(constraints, subject, resource): 
    """
    Evaluates constraints between subject and resource attributes.

    Args:
        constraints (list): Constraints to evaluate.
        subject (dict): Subject attributes.
        resource (dict): Resource attributes.

    Returns:
        bool: True if all constraints are met, otherwise False.
    """
    for constraint in constraints:
        sub_att = constraint["sub_att"]
        res_att = constraint["res_att"]
        operator = constraint["operator"]

        # Get the values of the subject and resource attributes
        sub_value = subject.get(sub_att)
        res_value = resource.get(res_att)

        # Check if values are None
        if sub_value is None or res_value is None:
            # print(f"Warning: Missing value for {sub_att} or {res_att}.")
            return False
        
        if operator == "equals":
            if sub_value != res_value:
                # print(f"Failed: {sub_value} != {res_value}")
                return False

        elif operator == "in":
            if sub_value not in res_value:
                # print(f"Failed: {sub_value} not in {res_value}")
                return False

        elif operator == "subset":
            # Ensure both values are sets before performing subset check
            sub_value_set = set(sub_value) if not isinstance(sub_value, set) else sub_value
            res_value_set = set(res_value) if not isinstance(res_value, set) else res_value
            if not sub_value_set.issubset(res_value_set):
                # print(f"Failed: {sub_value_set} is not a subset of {res_value_set}")
                return False

        elif operator == "contains": 
            # Convert strings to sets for intersection if needed
            if isinstance(sub_value, set) and isinstance(res_value, set):
                if not (sub_value & res_value):
                    # print(f"Failed: No intersection between {sub_value} and {res_value}")
                    return False
            else:
                # If one is not a set, convert strings to sets for comparison
                if isinstance(sub_value, str):
                    sub_value = set(sub_value)
                if isinstance(res_value, str):
                    res_value = {res_value}
                if not (sub_value & res_value):
                    # print(f"Failed: No intersection between {sub_value} and {res_value}")
                    return False

    return True








def find_matching_rule(subject, resource, action):
    for rule in abac_policy["rules"]:
        # Check if subCond matches subject
        if not evaluate_subject_condition(subject, rule['subCond']):
            # print(f"Subject condition not met for rule: {rule}")
            continue
        
        # Check if resCond matches resource
        if not evaluate_resource_condition(resource, rule['resCond']):
            # print(f"Resource condition not met for rule: {rule}")
            continue
        
        # # Check if acts matches action
        if not evaluate_action(rule['acts'], action):
            # print(f"Action not allowed for rule: {rule}")
            continue
        
        # # Check constraints (if any) with subject and resource
        if rule["cons"] and not evaluate_constraints(rule["cons"], subject, resource):
            # print(f"Constraint not met for rule: {rule}")
            continue
        
        # If all conditions pass, return the rule
        # print(f"Found matching rule: {rule}")
        return True  # Return True when a matching rule is found

    # print("No matching rule found")
    return False  # Return False if no matching rule is found


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
    subject = find_subject(sub_id)
    if not subject:
        return "Deny"

    resource = find_resource(res_id)
    if not resource:
        return "Deny"

    matching_rule = find_matching_rule(subject, resource, action)
    if matching_rule:
        return "Permit"

    return "Deny"


#TODO: Framework Feature 4: Policy Coverage Analysis
#TODO: Framework Feature 4: Policy Coverage Analysis
def analyze_policy_coverage():
    """
    Analyzes policy coverage by calculating authorizations for each rule
    and generating a heatmap.
    """
    rules = abac_policy["rules"]
    users = abac_policy["users"]
    resources = abac_policy["resources"]
    # Initialize data for analysis
    attributes = set()
    coverage_data = []
    for rule in rules:
        covered_authorizations = 0
        referenced_attributes = set()
        # Check all user-resource-action combinations inline
        for user in users:
            for resource in resources:
                for action in rule["acts"]:
                    # Inline evaluation logic
                    sub_cond_match = all(
                        attr in user and user[attr] in values
                        for attr, values in (rule["subCond"] or {}).items()
                    )
                    res_cond_match = all(
                        attr in resource and resource[attr] in values
                        for attr, values in (rule["resCond"] or {}).items()
                    )
                    cons_match = all(
                        user.get(cons["sub_att"]) == resource.get(cons["res_att"])
                        for cons in (rule["cons"] or [])
                    )
                    if sub_cond_match and res_cond_match and cons_match:
                        covered_authorizations += 1
        # Collect attributes used in the rule
        if rule["subCond"]:
            referenced_attributes.update(rule["subCond"].keys())
        if rule["resCond"]:
            referenced_attributes.update(rule["resCond"].keys())
        if rule["cons"]:
            for constraint in rule["cons"]:
                referenced_attributes.update([constraint["sub_att"], constraint["res_att"]])
        attributes.update(referenced_attributes)
        coverage_data.append((covered_authorizations, referenced_attributes))
    # Create a sorted list of attributes
    sorted_attributes = sorted(attributes)
    heatmap_matrix = np.zeros((len(rules), len(sorted_attributes)))
    # Populate the heatmap matrix
    for rule_index, (authorizations, referenced_attrs) in enumerate(coverage_data):
        for attr in referenced_attrs:
            attr_index = sorted_attributes.index(attr)
            heatmap_matrix[rule_index][attr_index] = authorizations
    # Generate the heatmap
    plt.figure(figsize=(10, 8))
    plt.imshow(heatmap_matrix, cmap="YlGn", aspect="auto")
    # Configure heatmap labels and color bar
    plt.xticks(ticks=np.arange(len(sorted_attributes)), labels=sorted_attributes, rotation=45, ha="right")
    plt.yticks(ticks=np.arange(len(rules)), labels=[f"Rule {i + 1}" for i in range(len(rules))])
    plt.colorbar(label="Number of Authorizations")
    plt.title("Policy Coverage Analysis Heatmap")
    plt.xlabel("Attributes")
    plt.ylabel("Rules")
    plt.tight_layout()
    plt.show()


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
    # test_parsing()

    # result = check_request("carDoc2","carPat2carItem","read")
    # print(f"Request: ('carDoc2,carPat2carItem,read')  => {result}")  

    # requests = load_requests()
    # if requests:
    #         for request in requests:
    #             sub_id, res_id, action = request
    #             # print(f"Request: {request}")
    #             result = check_request(sub_id, res_id, action)
    #             print(f"Request: {request} => {result}")   
    # pass
    # analyze_policy_coverage()
    # analyze_access_patterns()
    
# -------------------------------------------------


if __name__ == "__main__":
    main()
# -------------------------------------------------