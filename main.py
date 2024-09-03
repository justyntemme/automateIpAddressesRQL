import json
import logging
import os
from typing import Tuple, List
import git
import shutil
import requests

logging.basicConfig(level=logging.INFO)


# Global Variables
n = None  # To shorten line lengths
PC_URL = os.environ.get("PC_URL")
GIT_REPO_URL = "https://github.com/justyntemme/automateIpAddressesRQL"


def fetch_rql_file(repo_url):
    temp_dir = "temp_repo"

    try:
        # Clone the repository into the temporary directory.
        print(f"Cloning the repository from {repo_url} into {temp_dir}...")
        repo = git.Repo.clone_from(repo_url, temp_dir)
        print("Repository cloned successfully.")

        repo.git.checkout("main")

        # Construct the path to the rql.txt file.
        rql_file_path = os.path.join(temp_dir, "rql.txt")
        print(f"Looking for the file at {rql_file_path}...")

        if os.path.exists(rql_file_path):
            with open(rql_file_path, "r") as file:
                rql_content = file.read()
                print("File read successfully.")
        else:
            raise FileNotFoundError(
                "rql.txt does not exist in the root directory of the repo"
            )

        return rql_content

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

    finally:
        if os.path.exists(temp_dir):
            print(f"Cleaning up the temporary directory {temp_dir}...")
            shutil.rmtree(temp_dir)
            print("Cleanup successful.")


def format_security_groups(security_groups):
    """
    Takes an input array of security groups and returns a formatted string in the required format:
    ( \"sg-123456\", \"sg-123454\")
    """
    # Format each element in the array to be enclosed in double quotes and comma-separated
    formatted_groups = ", ".join(f'"{sg}"' for sg in security_groups)

    # Enclose the formatted string in parentheses
    formatted_string = f"( {formatted_groups} )"

    return formatted_string


def goRQL(
    token: str,
    cloud_account: str,
    cidr_ips: str,
    vpc_id: str,  # security_groups: str
) -> Tuple[int, str]:
    scanURL = PC_URL + "/search/config" if PC_URL is not None else exit(1)
    headers = {
        "accept": "application/json; charset=UTF-8",
        # "accept": "text/csv",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    # query = fetch_rql_file(GIT_REPO_URL)
    query = (
        f"config from cloud.resource where cloud.account = '{cloud_account}' "
        f"and api.name = 'aws-ec2-describe-security-groups' "
        f"AND json.rule = ipPermissions[*].ipv4Ranges[*].cidrIp exists "
        f"and ipPermissions[*].ipv4Ranges[?none(cidrIp is member of ({cidr_ips}))] exists "
        f'and vpcId contains "{vpc_id}" '
        # f"and groupId is member of (\"{security_groups.replace(',', '\", \"')}\")"
    )
    print(query)
    queryJSON = {
        "searchName": "My Search",
        "searchDescription": "Description of the search",
        "withResourceJson": True,
        # "timeRange": {"type": "relative", "value": {"unit": "minute", "amount": 10}},
        # "sort": [{"field": "ID", "direction": "asc"}],
        "limit": 10,
        "ID": "string",
        "query": query,
    }
    print(queryJSON["query"])
    # queryJSON = {
    #    "query": query,
    #    "timeRange": {"type": "relative", "value": {"unit": "hour", "amount": 24}},
    # }

    response = requests.post(
        scanURL, headers=headers, timeout=60, verify=False, json=queryJSON
    )
    return (response.status_code, response.text)


def generateCSPMToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = PC_URL + "/login"

    headers = {
        "accept": "application/json; charset=UTF-8",
        "content-type": "application/json",
    }
    body = {"username": accessKey, "password": accessSecret}
    response = requests.post(
        authURL, headers=headers, json=body, timeout=60, verify=False
    )

    if response.status_code == 200:
        data = json.loads(response.text)
        logging.info("Token acquired")
        return 200, data["token"]
    else:
        logging.error(
            "Unable to acquire spm token with error code: %s", response.status_code
        )

    return response.status_code, ""


def check_param(param):
    if isinstance(param, str):
        # Single parameter case
        param_value = os.environ.get(param)
        if param_value is None:
            logging.error(f"Missing {param}")
            raise ValueError(f"Missing {param}")
        return param_value
    elif isinstance(param, list):
        # List of parameters case
        param_values = []
        for p in param:
            param_value = os.environ.get(p)
            if param_value is None:
                logging.error(f"Missing {p}")
                raise ValueError(f"Missing {p}")
            param_values.append(param_value)
        return param_values
    else:
        raise TypeError("Parameter must be a string or a list of strings")


def main():
    P: Tuple[str, str, str, str, List[str], str] = (
        "PC_IDENTITY",
        "PC_SECRET",
        "PC_URL",
        "CLOUD_ACCOUNT",
        ["CIDR_IPS"],
        "VPC_ID",
    )
    accessKey, accessSecret, _ = map(check_param, P)
    responseCode, cspmToken = (
        generateCSPMToken(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )

    responseCode, content = goRQL(cspmToken) if cspmToken else (exit(1))
    logging.info(responseCode)
    logging.info(content)


if __name__ == "__main__":
    main()
