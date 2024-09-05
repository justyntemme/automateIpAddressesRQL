import json
import logging
import os
from typing import Tuple
import git
import shutil
import requests

logging.basicConfig(level=logging.INFO)


# Global Variables are snake case to match env variable expected
n = None  # To shorten line lengths
pcUrl = os.environ.get("pcUrl")
gitRepoUrl = "https://github.com/justyntemme/automateIpAddressesRQL"


def fetchIPRepository(repoUrl):
    tempDir = "tempRepo"

    try:
        # Clone the repository into the temporary directory.
        logging.info(f"Cloning the repository from {repoUrl} into {tempDir}...")
        repo = git.Repo.clone_from(repoUrl, tempDir)
        logging.info("Repository cloned successfully.")

        repo.git.checkout("main")

        # Construct the path to the rql.txt file.
        ipsFilePath = os.path.join(tempDir, "ips.txt")
        logging.info(f"Looking for the file at {ipsFilePath}...")

        if os.path.exists(ipsFilePath):
            with open(ipsFilePath, "r") as file:
                ipsContent = file.read()
                logging.info("File read successfully.")
        else:
            raise FileNotFoundError(
                "ips.txt does not exist in the root directory of the repo"
            )
        logging.info(ipsContent)
        return ipsContent

    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return None

    finally:
        if os.path.exists(tempDir):
            logging.info(f"Cleaning up the temporary directory {tempDir}...")
            shutil.rmtree(tempDir)
            logging.info("Cleanup successful.")


def goRQL(
    token: str,
    cloudAccount: str,
    cidr_ips: str,
    vpcId: str,
    securityGroups: str,  # security_groups: str
) -> Tuple[int, str]:
    scanURL = pcUrl + "/search/config" if pcUrl is not None else exit(1)
    headers = {
        "accept": "application/json; charset=UTF-8",
        # "accept": "text/csv",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    ipAddresses = fetchIPRepository(gitRepoUrl)

    query = (
        f"config from cloud.resource where cloud.account = '{cloudAccount}' "
        f"and api.name = 'aws-ec2-describe-security-groups' "
        f"AND json.rule = ipPermissions[*].ipv4Ranges[*].cidrIp exists "
        f"and ipPermissions[*].ipv4Ranges[?none(cidrIp is member of ({ipAddresses}))] exists "
        f'and vpcId contains "{vpcId}" '
        f"and groupId is member of ({securityGroups})"
    )
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
    response = requests.post(
        scanURL, headers=headers, timeout=60, verify=False, json=queryJSON
    )
    return (response.status_code, response.text)


def generateCSPMToken(accessKey: str, accessSecret: str) -> Tuple[int, str]:
    authURL = pcUrl + "/login"

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


def checkParam(param):
    if isinstance(param, str):
        # Single parameter case
        paramValue = os.environ.get(param)
        if paramValue is None:
            logging.error(f"Missing {param}")
            raise ValueError(f"Missing {param}")
        return paramValue
    elif isinstance(param, list):
        # List of parameters case
        paramValues = []
        for p in param:
            paramValue = os.environ.get(p)
            if paramValue is None:
                logging.error(f"Missing {p}")
                raise ValueError(f"Missing {p}")
            paramValues.append(paramValue)
        return paramValues
    else:
        raise TypeError("Parameter must be a string or a list of strings")


def main():
    P: Tuple[str, str, str, str, str, str, str] = (
        "pcIdentity",
        "pcSecret",
        "pcUrl",
        "cloudAccount",
        "cidrIps",
        "vpcId",
        "securityGroups",
    )
    accessKey, accessSecret, _, cloudAccount, cidrIps, vpcId, securityGroups = map(
        checkParam, P
    )

    responseCode, cspmToken = (
        generateCSPMToken(accessKey, accessSecret)
        if accessKey and accessSecret
        else (None, None)
    )
    responseCode, content = (
        goRQL(cspmToken, cloudAccount, cidrIps, vpcId, securityGroups)
        if cspmToken
        else (exit(1))
    )
    logging.info(responseCode)
    logging.info(content)


if __name__ == "__main__":
    main()
