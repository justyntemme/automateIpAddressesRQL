import json
import logging
import os
from typing import Tuple
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
        rql_file_path = os.path.join(temp_dir, "test-rql.txt")
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


def goRQL(token: str) -> Tuple[int, str]:
    scanURL = PC_URL + "/search/config" if PC_URL is not None else exit(1)
    headers = {
        #    "accept": "application/json; charset=UTF-8",
        "accept": "text/csv",
        "content-type": "application/json",
        "Authorization": f"Bearer {token}",
    }
    query = fetch_rql_file(GIT_REPO_URL)
    print(query)
    queryJSON = {
        "query": query,
        "timeRange": {"type": "relative", "value": {"unit": "hour", "amount": 24}},
    }

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


def check_param(param_name: str) -> str:
    param_value = os.environ.get(param_name)
    if param_value is None:
        logging.error(f"Missing {param_name}")
        raise ValueError(f"Missing {param_name}")
    return param_value


def main():
    P: Tuple[str, str, str] = ("PC_IDENTITY", "PC_SECRET", "PC_URL")
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
