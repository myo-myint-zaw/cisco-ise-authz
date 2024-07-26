"""
Author: Myo Myint Zaw
Purpose: Retrieve Authorization Profiles and Rules from Cisco ISE and save them into a excel 
Date: 25-Jul-2024
"""

import sys
import json
import warnings
from pprint import pprint
import yaml
import click
import pandas
import requests
import numpy as np

from tabulate import tabulate
from requests.exceptions import ConnectionError
# from generate_payload_authz_profiles import NetdevAP
# from generate_payload_authz_rules import NetdevAR

requests.packages.urllib3.disable_warnings()
warnings.simplefilter(action="ignore", category=FutureWarning)

#Global
ISE_HOST = None
AUTHORIZATION = None
EXCEL_FILE = None
SHEET_NAME = None
START_RANGE = 1
END_RANGE = 100

az_profiles = []
az_rules = []

def get_profiles():
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = "api/v1/policy/network-access/authorization-profiles"
    url = f"https://{ISE_HOST}/{endpoint}"
    r = requests.get(url, headers=headers, verify=False)
    data = r.json()

    status_code = r.status_code

    if status_code == 200:
        return data

    else:
        err_output = r.json()["message"]
        print(f"Err: {err_output}")

def get_profile_details(name):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = "ers/config/authorizationprofile/name"
    url = f"https://{ISE_HOST}:9060/{endpoint}/{name}"
    r = requests.get(url, headers=headers, verify=False)
    data = r.json()

    status_code = r.status_code

    if status_code == 200:
        return data["AuthorizationProfile"]

    else:
        err_output = r.json()["message"]
        print(f"Err: {err_output}")

def get_policyid():
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = "api/v1/policy/network-access/policy-set"
    url = f"https://{ISE_HOST}/{endpoint}"
    r = requests.get(url, headers=headers, verify=False)
    data = r.json()

    status_code = r.status_code
    
    pol_set = {}
    if status_code == 200:
        for i in data["response"]:
            pol_set[i["name"]] = i["id"]
        return pol_set

    else:
        err_output = r.json()["message"]
        print(f"Err: {err_output}")


def get_authz_rules(pol_id):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = f"api/v1/policy/network-access/policy-set/{pol_id}/authorization"
    url = f"https://{ISE_HOST}/{endpoint}"
    r = requests.get(url, headers=headers, verify=False)
    data = r.json()

    status_code = r.status_code
    
    pol_set = []
    if status_code == 200:
        for i in data["response"]:
            if not i["rule"]["default"]:
                pol_set.append(i)

        return pol_set

    else:
        err_output = r.json()["message"]
        print(f"Err: {err_output}")


def generate_globals(config_file):
    with open(config_file, "r") as f:
        ise_info = yaml.safe_load(f)
    
    global ISE_HOST, AUTHORIZATION, EXCEL_FILE, SHEET_NAME, START_RANGE, END_RANGE
    ISE_HOST = ise_info["ise_device"]["host_ip"].strip()
    AUTHORIZATION = ise_info["ise_device"]["base64_auth"].strip()
    EXCEL_FILE = ise_info["excel"]["excel_file"].strip()
    SHEET_NAME = ise_info["excel"]["sheet_name"].strip()
    START_RANGE = ise_info["excel"]["rows_range"]["start"]
    END_RANGE = ise_info["excel"]["rows_range"]["end"]

@click.command()
@click.option(
    "--config-file",
    type=click.Path(exists=True),
    required=True,
    help="Pass ise device configs in a yml file Eg: ise_config.yml",
)

def main(config_file):
    generate_globals(config_file)
    option = """\nYou are retrieving Cisco ISE configurations. The following options are available.
     1) Authorization Profiles
     2) Authorization Rules"""

    print(option)
    user_input = input("\nPlease choose option 1 or 2 from the above menu and press enter: ")
    print("\n\n", "-" * 96)
    print("Processing... please wait")

    if int(user_input) == 1:
        print("Getting...... authorization profiles name")
        profiles = get_profiles()
        az_profiles = []

        print("Getting...... authorization profiles details")
        for i in profiles:
            prof_detail = get_profile_details(i["name"])
            if "default profile" not in prof_detail["description"].lower():
                az_profiles.append(prof_detail)
                #print(prof_detail)
        
        for i in az_profiles:
            f_profiles = {}
            f_profiles["name"] = i["name"]
            f_profiles["id"] = i["id"]
            f_profiles["description"] = i["description"]
            for attr in i["advancedAttributes"]:
                f_profiles[attr["leftHandSideDictionaryAttribue"]["attributeName"]] = attr["rightHandSideAttribueValue"]["value"]
            
            az_profiles.append(f_profiles)
        
        print("Saving....... authorization profiles details to excel file")
        df = pandas.DataFrame.from_dict(az_profiles)
        df.index = df.index + 1
        df.to_excel('existing_cisco_ise_authz_profile.xlsx', sheet_name='Authz_Profile') #index=False
        print("Completed.... authorization profiles details have been saved to excel file: existing_cisco_ise_authz_profile.xlsx\n")

    elif int(user_input) == 2:
        print("Getting...... authorization rules name")
        policyid = get_policyid()
        print("Getting...... authorization rules details")
        
        for k,v in policyid.items():
            rule_detail = get_authz_rules(v)

            for i in rule_detail:
                num = 0
                az_rule = {}
                az_rule["pol_set_name"] = k
                az_rule["name"] = i["rule"]["name"]
                az_rule["id"] = i["rule"]["id"]
                az_rule["state"] = i["rule"]["state"]
                az_rule["profile"] = i["profile"][0]
                try:
                    for ii in i["rule"]["condition"]["children"]:
                        num += 1
                        attr_name = ii["attributeName"] + str(num)
                        az_rule[attr_name] = ii["attributeValue"]
                except:
                    attr_name = i["rule"]["condition"]["attributeName"] + str(1)
                    az_rule[attr_name] = i["rule"]["condition"]["attributeValue"]

                az_rules.append(az_rule)
            
        print("Saving....... authorization rules details to excel file")
        df = pandas.DataFrame.from_dict(az_rules)
        df.index = df.index + 1
        df.to_excel('existing_cisco_ise_authz_rules.xlsx', sheet_name='Authz_Rule') #index=False
        print("Completed.... authorization rules details have been saved to excel file: existing_cisco_ise_authz_rules.xlsx\n")


if __name__ == "__main__":
    main()