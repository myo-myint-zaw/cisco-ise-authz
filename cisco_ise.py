"""
Author: Myo Myint Zaw
Purpose: Create Authorization Profiles and Rules on Cisco ISE
Date: 12-Jul-2024
"""

from asyncio import eager_task_factory
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
from generate_payload_authz_profiles import NetdevAP
from generate_payload_authz_rules import NetdevAR

requests.packages.urllib3.disable_warnings()
warnings.simplefilter(action="ignore", category=FutureWarning)

#Global
ISE_HOST = None
AUTHORIZATION = None
EXCEL_FILE = None
SHEET_NAME = None
START_RANGE = 1
END_RANGE = 100

payload = []
pol_id = {}


def create_authz_profile(role_no, name, payload):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = "ers/config/authorizationprofile"
    url = f"https://{ISE_HOST}:9060/{endpoint}"
    r = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)

    status_code = r.status_code

    if status_code == 201:
        print(f" {role_no}. Successfully created the authorization profile - {name}")
    else:
        # err_output = r.json()["ERSResponse"]["messages"][0]["title"]
        # print(f" {role_no}. Err: {err_output}")
        error_output = r.json()
        print(error_output)
    return status_code


def get_policyid(policy_set_name):
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

    if status_code == 200:
        for i in data["response"]:
            if i["name"] == policy_set_name:
                policyid = i["id"]
                return policyid
    else:
        err_output = r.json()["message"]
        print(f"Err: {err_output}")


def create_authz_rule(role_no, name, policyid, payload):
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Authorization': AUTHORIZATION,
    }

    endpoint = f"api/v1/policy/network-access/policy-set/{policyid}/authorization"
    url = f"https://{ISE_HOST}/{endpoint}"
    r = requests.post(url, headers=headers, data=json.dumps(payload), verify=False)

    status_code = r.status_code

    if status_code == 201:
        print(f" {role_no}. Successfully created the authorization rule - {name}")
    else:
        err_output = r.json()["message"]
        print(f" {role_no}. Err: {err_output}")


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
    data = pandas.read_excel(EXCEL_FILE, sheet_name=SHEET_NAME, engine='openpyxl')
    data = data.replace({np.nan: None})  # Replace all nan values to None in DataFrame
    pandas.option_context("display.max_colwidth", 0)

    if SHEET_NAME == "Authz_Profile":
        print(tabulate(data.iloc[START_RANGE - 1 :END_RANGE, [0,1,3,4,5,6]], headers="keys", tablefmt="psql", showindex=False))
        to_confirm = input("Enter ok to create the above Authorization Profiles: ").strip()
        if to_confirm.lower() != "ok":
            sys.exit(-1)
        print("\n\n", "-" * 96)
        print("Processing... Please wait\n")

        for i in data.values[START_RANGE - 1 :END_RANGE]:
            name, description, primary_dns = i[1], i[2], i[3]
            secondary_dns, domain, address_pool = i[4], i[5], i[6]
            gen_payload = NetdevAP(name, description, primary_dns, secondary_dns, domain, address_pool).to_json()

            payload_attr = {}
            payload_attr["role_no"] = i[0]
            payload_attr["rule_name"] = name
            payload_attr["r_payload"] = gen_payload

            payload.append(payload_attr)

        for i in payload:
            rcode = create_authz_profile(i["role_no"], i["rule_name"], i["r_payload"])
            if rcode != 201:
                print("Error")
                break
            
            


    if SHEET_NAME == "Authz_Rule":
        print(tabulate(data.iloc[START_RANGE - 1 :END_RANGE, [0,1,2,3,4,5,6]], headers="keys", tablefmt="psql", showindex=False))
        to_confirm = input("Enter ok to create the above Authorization Rules: ").strip()
        if to_confirm.lower() != "ok":
            sys.exit(-1)
        print("\n\n", "-" * 96)
        print("Processing... Please wait\n")

        pol_set = set([])
        for i in data.values[START_RANGE - 1 :END_RANGE]:
            rule_name, ext_grp_name1, ext_grp_name2 = i[2], i[3], i[4]
            username1, username2, profile_name, dn1, dn2 = i[5], i[6], i[7], i[8], i[9]
            gen_payload = NetdevAR(rule_name, ext_grp_name1, ext_grp_name2, username1, username2, profile_name, dn1, dn2).to_json()
            
            pol_set.add(i[1])

            payload_attr = {}
            payload_attr["role_no"] = int(i[0])
            payload_attr["pol_set_name"] = i[1]
            payload_attr["rule_name"] = rule_name
            payload_attr["r_payload"] = gen_payload

            payload.append(payload_attr)

        for i in pol_set:
            _id = policyid = get_policyid(i)
            if _id != None:
                pol_id[i] = _id
            else:
                print(f" Err: Policy set name not found - {i}")

        if policyid != None:
            for i in payload:
                pol_set_n = i["pol_set_name"]
                create_authz_rule(i["role_no"], i["rule_name"], pol_id[pol_set_n], i["r_payload"])


if __name__ == "__main__":
    main()