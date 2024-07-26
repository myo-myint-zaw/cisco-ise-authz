"""
Author: Myo Myint Zaw
Purpose: Generate payload to create Cisco ISE Authorization Profiles 
Date: 12-Jul-2024
"""


class NetdevAR:
    def __init__(
        self,
#        pol_set_name,
        rule_name,
        ext_grp_name1,
        ext_grp_name2,
        username1,
        username2,
        profile_name,
        dn1,
        dn2,
    ):

        self.oneextgroup = {
            "link": None,
            "conditionType": "ConditionAttributes",
            "isNegate": False,
            "dictionaryName": ext_grp_name1,
            "attributeName": "ExternalGroups",
            "operator": "equals",
            "dictionaryValue": None,
            "attributeValue": f"CN={rule_name.replace("-Rule", "")},{dn1}"
        }

        self.twoextgroups = {
            "link": None,
            "conditionType": "ConditionOrBlock",
            "isNegate": False,
            "children": [
                {
                    "link": None,
                    "conditionType": "ConditionAttributes",
                    "isNegate": False,
                    "dictionaryName": ext_grp_name1,
                    "attributeName": "ExternalGroups",
                    "operator": "equals",
                    "dictionaryValue": None,
                    "attributeValue": f"CN={rule_name.replace("-Rule", "")},{dn1}"
                },
                {
                    "link": None,
                    "conditionType": "ConditionAttributes",
                    "isNegate": False,
                    "dictionaryName": ext_grp_name2,
                    "attributeName": "ExternalGroups",
                    "operator": "equals",
                    "dictionaryValue": None,
                    "attributeValue": f"CN={rule_name.replace("-Rule", "")},{dn2}"
                }
            ]
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
            "conditionType": "ConditionOrBlock",
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

        if ext_grp_name2 != None:
            self.payload["rule"]["condition"] = self.twoextgroups
        elif ext_grp_name1 != None:
            self.payload["rule"]["condition"] = self.oneextgroup

        if username2 != None:
            self.payload["rule"]["condition"] = self.twousernames
        elif username1 != None:
            self.payload["rule"]["condition"] = self.oneusername


    def to_json(self):
        return self.payload
