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
# ------------------------------------------------- hardcode rules 
def add_hardcoded_rules():
    global abac_policy  # This will ensure you're modifying the global abac_policy

    abac_policy["rules"] = [
       
        # Rule 1: A nurse can add an item in a HR for a patient in the ward in which they work
        {
            "subCond": {"position": {"nurse"}},  # Subject must have position = nurse
            "resCond": {"type": {"HR"}},  # Resource type must be HR
            "acts": {"addItem"},  # Allowed action is addItem
            "cons":[{
                "sub_att": "ward",
                "operator": "equals",  # Constraint: ward must match between subject and resource
                "res_att": "ward"
            }
            ]
        },

        # Rule 2: A user can add an item in an HR for a patient treated by one of the teams they are a member of
        {
            "subCond": {},  # No specific conditions on the subject
            "resCond": {"type": {"HR"}},  # Resource type must be HR
            "acts": {"addItem"},
            "cons": [
                {
                "sub_att": "teams",
                "operator": "subset",  # Constraint: subject's teams must be a subset of treatingTeam
                "res_att": "treatingTeam"
            }
            ]
        },

        # Rule 3: A user can add an item with topic "note" in their own HR
        {
            "subCond": {},  # No specific conditions on the subject
            "resCond": {"type": {"HR"}},  # Resource type must be HR
            "acts": {"addNote"},
            "cons": [
                {
                    "sub_att": "uid",
                    "operator": "equals",  # Constraint: subject's uid must match the resource's uid (patient)
                    "res_att": "patient"
                 }
            ]
        },

        # Rule 4: A user can add an item with topic "note" in the HR of a patient for which they are an agent
        {
            "subCond": {},  # No specific conditions on the subject
            "resCond": {"type": {"HR"}},  # Resource type must be HR
            "acts": {"addNote"},
            "cons": [
                {
                "sub_att": "agentFor",
                "operator": "in",  # Constraint: subject's agentFor must include the patient
                "res_att": "patient"
            }
            ]
        },

        # Rule 5: The author of an item can read it
        {
            "subCond": {},  # No specific conditions on the subject
            "resCond": {"type": {"HRitem"}},  # Resource type must be HRitem
            "acts": {"read"},
            "cons": [
                {
                "sub_att": "uid",
                "operator": "equals",  # Constraint: subject's uid must match the resource's uid (author)
                "res_att": "author"
            }
            ]
        },

        # Rule 6: A user can read an item in a HR for a patient treated by one of the teams they are a member of,
        # if the topics of the item are among their specialties
        {
            "subCond": {},  # No specific conditions on the subject
            "resCond": {"type": {"HRitem"}},  # Resource type must be HRitem
            "acts": {"read"},
            "cons": [
                {
                    "sub_att": "specialties",
                    "operator": "subset",  # Constraint: subject's specialties must contain resource's topics
                    "res_att": "topics"
                },
                {
                    "sub_att": "level",
                    "operator": "equal",  # Constraint: subject's level must be equal to resource's difficulty
                    "res_att": "difficulty"
                }
            ]
        }
    ]
    


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
    add_hardcoded_rules()

    # print("Users:")
    # for user in abac_policy["users"]:
    #     print(user)
    # print("\nResources:")
    # for resource in abac_policy["resources"]:
    #     print(resource)
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
    """Evaluate if subject satisfies the subCond condition."""
    for attr, values in subCond.items():
        # Check if the attribute exists in the subject and if its value is in the set of allowed values in subCond
        if attr not in subject or subject[attr] not in values:
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
        constraints (dict): Constraints to evaluate.
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
            return False

        # Perform the actual comparison based on the operator
        if operator == "equals":
            if sub_value != res_value:
                return False
        elif operator == "in":
            if sub_value not in res_value:
                return False
        elif operator == "subset":
            if not sub_value.issubset(res_value):
                return False
        elif operator == "contains":
            if not (set(sub_value) & res_value):
                return False
        # Add more operators as necessary

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

    print("No matching rule found")
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

#TODO: Framework Feature 5: Analyze Resource Access Patterns
        
def main():

    load_abac_files()
    test_parsing()

    # result = check_request("oncDoc1","oncPat1oncItem","read")
    # print(f"Request: (oncDoc1,oncPat1oncItem,read)  => {result}")  

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