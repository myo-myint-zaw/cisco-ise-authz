"""
Author: Myo Myint Zaw
Purpose: Generate payloads to create Cisco ISE Authorization Profiles 
Date: 12-Jul-2024
"""


class NetdevAP:
    def __init__(
        self,
        name,
        description,
        primary_dns,
        secondary_dns,
        domain,
        address_pool,
    ):

        self.primarydns = {
            "leftHandSideDictionaryAttribue": {
                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                "dictionaryName": "Cisco-VPN3000",
                "attributeName": "CVPN3000/ASA/PIX7x-Primary-DNS",
            },
            "rightHandSideAttribueValue": {
                "AdvancedAttributeValueType": "AttributeValue",
                "value": primary_dns,
            },
        }

        self.secondarydns = {
            "leftHandSideDictionaryAttribue": {
                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                "dictionaryName": "Cisco-VPN3000",
                "attributeName": "CVPN3000/ASA/PIX7x-Secondary-DNS",
            },
            "rightHandSideAttribueValue": {
                "AdvancedAttributeValueType": "AttributeValue",
                "value": secondary_dns,
            },
        }

        self.domain = {
            "leftHandSideDictionaryAttribue": {
                "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                "dictionaryName": "Cisco-VPN3000",
                "attributeName": "CVPN3000/ASA/PIX7x-IPSec-Default-Domain",
            },
            "rightHandSideAttribueValue": {
                "AdvancedAttributeValueType": "AttributeValue",
                "value": domain,
            },
        }

        self.payload = {
            "AuthorizationProfile": {
                "name": name,
                "description": description,
                "advancedAttributes": [
                    {
                        "leftHandSideDictionaryAttribue": {
                            "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                            "dictionaryName": "Cisco-VPN3000",
                            "attributeName": "CVPN3000/ASA/PIX7x-Address-Pools",
                        },
                        "rightHandSideAttribueValue": {
                            "AdvancedAttributeValueType": "AttributeValue",
                            "value": address_pool,
                        },
                    },
                    {
                        "leftHandSideDictionaryAttribue": {
                            "AdvancedAttributeValueType": "AdvancedDictionaryAttribute",
                            "dictionaryName": "Radius",
                            "attributeName": "Service-Type",
                        },
                        "rightHandSideAttribueValue": {
                            "AdvancedAttributeValueType": "AttributeValue",
                            "value": "8",
                        },
                    },
                ],
                "accessType": "ACCESS_ACCEPT",
                "authzProfileType": "SWITCH",
                "trackMovement": False,
                "agentlessPosture": False,
                "serviceTemplate": False,
                "easywiredSessionCandidate": False,
                "profileName": "Cisco",
            }
        }

        # for i in (primary_dns, secondary_dns, domain):
        #     if str(i) != None:
        #         self.payload["AuthorizationProfile"]["advancedAttributes"].append(self.i)
        #     else:
        #         print("not assign", NA)

        if primary_dns != None:
            self.payload["AuthorizationProfile"]["advancedAttributes"].append(self.primarydns)
        if secondary_dns != None:
            self.payload["AuthorizationProfile"]["advancedAttributes"].append(self.secondarydns)
        if domain != None:
            self.payload["AuthorizationProfile"]["advancedAttributes"].append(self.domain)


    def to_json(self):
        return self.payload
