import json

data = {
    "ERSLdap": {
        "id": "23a541c0-4ba3-11ef-85a1-5e2f4789f543",
        "name": "GoMAX_LDAPS",
        "description": "GoMAX_LDAPS",
        "generalSettings": {
            "userObjectClass": "Objectclass",
            "userNameAttribute": "Name",
            "groupNameAttribute": "Group",
            "groupObjectClass": "Objectclass",
            "groupMapAttributeName": "Group",
            "certificate": "Certificate ",
            "schema": "CUSTOM",
            "groupReference": "GROUP_TO_USER",
            "groupMemberReference": "DISTINGUISHED_NAME",
            "userInfoAttributes": {
                "firstName": "",
                "department": "",
                "lastName": "",
                "organizationalUnit": "",
                "jobTitle": "",
                "locality": "",
                "email": "",
                "stateOrProvince": "",
                "telephone": "",
                "country": "",
                "streetAddress": ""
            }
        },
        "connectionSettings": {
            "primaryServer": {
                "hostName": "192.168.12.1",
                "port": 389,
                "maxConnections": 20,
                "serverTimeout": 10,
                "useAdminAccess": False,
                "enableSecureConnection": False,
                "enableServerIdentityCheck": False,
                "enableForceReconnect": False
            },
            "ldapNodeData": [],
            "failoverToSecondary": False,
            "failbackRetryDelay": 5,
            "specifyServerForEachISENode": False,
            "alwaysAccessPrimaryFirst": False
        },
        "directoryOrganization": {
            "userDirectorySubtree": "CN=Groups_GoMAX,CN=Groups_SGVPN,CN=sgvpn,DC=sgvpn,DC=sgnet,DC=gov,DC=sg",
            "groupDirectorySubtree": "CN=Groups_GoMAX,CN=Groups_SGVPN,CN=sgvpn,DC=sgvpn,DC=sgnet,DC=gov,DC=sg",
            "macFormat": "DASH",
            "stripPrefix": False,
            "stripSuffix": False,
            "prefixSeparator": "\\",
            "suffixSeparator": ""
        },
        "groups": {
            "groupsNames": [
            ]
        },
        "attributes": {
            "attributes": []
        },
        "enablePasswordChangeLDAP": False
    }
}


for i in range(1,501):

    if i < 10:    
        i = str(i).zfill(2)    
        grp = "CN=PILOT-VPN-" + str(i) + ",CN=Groups_GoMAX,CN=Groups_SGVPN,CN=sgvpn,DC=sgvpn,DC=sgnet,DC=gov,DC=sg"
    else:
        grp = "CN=PILOT-VPN-" + str(i) + ",CN=Groups_GoMAX,CN=Groups_SGVPN,CN=sgvpn,DC=sgvpn,DC=sgnet,DC=gov,DC=sg"
        
    data["ERSLdap"]["groups"]["groupsNames"].append(grp)

with open("gomax_ldaps_groups_payload.txt", "w") as gmx:
    payload = json.dumps(data)    
    gmx.write(str(payload))    

