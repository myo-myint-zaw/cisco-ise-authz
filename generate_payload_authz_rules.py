"""
Author: Myo Myint Zaw
Purpose: Generate payload to create Cisco ISE Authorization Profiles 
Date: 12-Jul-2024
"""


class NetdevAR:
    def __init__(
        self,
        policy_set_name,
        rule_name,
        external_group_name,
        username1,
        username2,
        profile_name,
    ):

        self.extgroup = {
            "link": None,
            "conditionType": "ConditionAttributes",
            "isNegate": False,
            "dictionaryName": external_group_name,
            "attributeName": "ExternalGroups",
            "operator": "equals",
            "dictionaryValue": None,
            "attributeValue": f"CN={rule_name},CN=Groups_GoMAX,CN=Groups_SGVPN,CN=sgvpn,DC=sgvpn,DC=sgnet,DC=gov,DC=sg"
        }

        self.oneusername = {
            "link": None,
            "conditionType": "ConditionAttributes",
            "isNegate": False,
            "dictionaryName": "Network Access",
            "attributeName": "UserName",
            "operator": "equals",
            "dictionaryValue": None,
            "attributeValue": username1
        }

        self.twousernames = {
            "link": None,
            "conditionType": "ConditionAndBlock",
            "isNegate": False,
            "children": [
                {
                    "link": None,
                    "conditionType": "ConditionAttributes",
                    "isNegate": False,
                    "dictionaryName": "Network Access",
                    "attributeName": "UserName",
                    "operator": "equals",
                    "dictionaryValue": None,
                    "attributeValue": username1
                },
                {
                    "link": None,
                    "conditionType": "ConditionAttributes",
                    "isNegate": False,
                    "dictionaryName": "Network Access",
                    "attributeName": "UserName",
                    "operator": "equals",
                    "dictionaryValue": None,
                    "attributeValue": username2
                }
            ]
        }

        self.payload = {
            "rule": {
                "default": False,
                "name": rule_name,
                "state": "enabled",
                "condition": {}
            },
            "profile": [
                profile_name
            ],
            "securityGroup": None
        }

        if external_group_name != None:
            self.payload["rule"]["condition"] = self.extgroup
        if username2 != None:
            self.payload["rule"]["condition"] = self.twousernames
        elif username1 != None:
            self.payload["rule"]["condition"] = self.oneusername


    def to_json(self):
        return self.payload
