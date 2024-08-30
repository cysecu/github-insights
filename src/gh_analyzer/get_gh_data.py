import argparse
import json
import logging  # Import the logging module
import os
import requests
import subprocess
import time
from datetime import datetime
# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def write_json_to_file(data: dict, filename: str) -> None:
    """
    (Over)Writes a dictionary to a JSON file.

    Parameters:
        data (dict): The data to write to the file.
        filename (str): The name of the file to write the data to.

    Returns:
        None
    """
    dir_path, file_name = os.path.split(filename)
    if dir_path and not os.path.exists(dir_path):
        os.makedirs(dir_path)

    if os.path.exists(file_name):
        logging.info(f"File {file_name} already exists and will be overwritten.")
    else:
        logging.info(f"File {file_name} does not exist and will be created.")

    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

    logging.info(f"Data written to {filename}")


def request_pagination(url, headers) -> list:
    """
    Fetches paginated data from a given URL.

    Parameters:
        url (str): The initial URL to fetch data from.
        headers (dict): The headers to include in the request.

    Returns:
        list: A list of results obtained from the paginated API.
    """
    results = []
    if "?per_page=100" not in url:
        url += "?per_page=100"
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            results.extend(response.json())
            if 'next' in response.links:
                url = response.links['next']['url']
            else:
                url = None
        else:
            logging.error(f"Failed to fetch data: {response.status_code}")
            break

    return results


def get_organization_dependabot_alerts_gh(headers) -> list:
    """
    Fetches Dependabot alerts for the organization from GitHub.

    Parameters:
        headers (dict): The headers to include in the request.

    Returns:
        list: A list of Dependabot alerts obtained from the GitHub API.
    """
    url = f"https://api.github.com/orgs/moia-dev/dependabot/alerts"
    results = request_pagination(url, headers)
    return results


def get_repository_sbom(repo, headers) -> dict:
    """
    Fetches the Software Bill of Materials (SBOM) for a given repository from GitHub.

    Parameters:
        repo (dict): A dictionary containing repository information.
        headers (dict): The headers to include in the request.

    Returns:
        dict: A dictionary containing the SBOM data for the repository.
    """

    url = f"{repo['url']}/dependency-graph/sbom"
    result = request_pagination(url, headers)
    return result


def get_repository_languages(repo, headers) -> dict:
    """
    Fetches the Software Bill of Materials (SBOM) for a given repository from GitHub.

    Parameters:
        repo (dict): A dictionary containing repository information.
        headers (dict): The headers to include in the request.

    Returns:
        dict: A dictionary containing the SBOM data for the repository.
    """

    url = f"{repo['languages_url']}"
    result = request_pagination(url, headers)
    return result


def repositories_list_gh(headers) -> list:
    """
    Fetches a list of repositories from the GitHub organization.

    Parameters:
        headers (dict): The headers to include in the request.

    Returns:
        list: A list of repositories obtained from the GitHub API.
    """
    url = f"https://api.github.com/orgs/moia-dev/repos"
    results = request_pagination(url, headers)
    return results


def get_repository_list(args: dict, headers: dict) -> dict:
    """
    Fetches a list of repositories based on the action specified in args.
    Load from GH or local

    Parameters:
        args (dict): A dictionary containing the action and other parameters.
        headers (dict): The headers to include in the request.

    Returns:
        dict: A dictionary of repositories.
    """

    repos = {}
    if args.action in ["full", "list-repos"]:
        logging.info(f"load repos from GitHub")
        repos = repositories_list_gh(headers)

    elif args.action == "check-repofile":
        logging.info(f"load repos from localfile: {args.input_file_repos}")
        with open(args.input_file_repos, 'r') as f:
            repos = json.load(f)
    else:
        pass

    return repos


def check_repository_dependabot_enabled_gh(repo, headers) -> bool:
    """
    Checks if the dependabot alerts are enabled for a given repository from GitHub.

    Parameters:
        repo (dict): A dictionary containing repository information.
        headers (dict): The headers to include in the request.

    Returns:
        bool: True if the dependabot alerts are enabled (code 204), False otherwise.
    """
    url = f"{repo['url']}/vulnerability-alerts"
    response = requests.get(url, headers=headers)
    return response.status_code == 204


def get_repository_dependabot_alerts_gh(repo: dict, headers: dict) -> list:
    """
    Fetches the dependabot alerts for a given repository from GitHub.

    Parameters:
        repo (dict): A dictionary containing repository information.
        headers (dict): The headers to include in the request.

    Returns:
        list: A list of dependabot alerts.
    """
    url = f"{repo['url']}/dependabot/alerts"
    result = request_pagination(url, headers)
    return result


def get_repository_data_gh(args, headers, repos) -> dict:
    """
    Processes repository data and checks for dependabot status.

    Parameters:
        args (argparse.Namespace): The parsed command-line arguments.
        headers (dict): The headers for GitHub API requests.
        repos (list): A list of repositories to process.

    Returns:
        dict: A dictionary containing processed repository data.
    """
    logging.info(f"Number of Repositories: {len(repos)}")
    dep_yes = 0
    dep_no = 0
    rep_no = 0 

    repository_data = {}
    for repo in repos:
        rep_no += 1

        # check repos - disabled, archived

        repo_identifier = repo["full_name"]
        repo_record = repo

        logMsg = f"{rep_no}. {repo['full_name']}"
        if check_repository_dependabot_enabled_gh(repo, headers):
            dep_yes += 1
            repo_record["dependabot_enabled"] = True
            alerts = get_repository_dependabot_alerts_gh(repo, headers)
            repo_record["dependabot_alerts"] = alerts
            logMsg += " has dependabot enabled and {len(alerts)} alerts"

        else:
            dep_no += 1
            repo_record["dependabot_enabled"] = False
            repo_record["dependabot_alerts"] = []
            logMsg += " has dependabot disabled"

        write_json_to_file(repo_record, f"{repo_identifier}.json")

        languages_data = get_repository_languages(repo, headers)        
        repo_record["languages"] = languages_data
        write_json_to_file(languages_data, f"{repo_identifier}_languages.json")

        repository_data[repo_identifier] = repo_record
        logging.info(logMsg)  # Log an info message

    logging.info(f"{dep_yes}/{len(repos)} have dependabot activated, should be {dep_no} repos without")

    return repository_data


def get_tokenized_header(args):
    """
    Retrieves a tokenized header for GitHub API requests.

    Args:
        args (argparse.Namespace): The arguments containing item_name and item_field for vault.

    Returns:
        dict: A dictionary containing the headers for GitHub API requests, or None if token retrieval failed.
    """
    
    item_name_vault = args.item_name_vault
    item_field_vault = args.item_field_vault

    token = get_token_from_1password(item_name_vault, item_field_vault)
    if not token:
        logging.error(f"no token found for auth")
        return None
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28"
    }

    return headers

def get_token_from_1password(item_name: str, field_name: str) -> str:
    """
    Retrieves a token from 1Password.

    Parameters:
        item_name (str): The name of the item in 1Password.
        field_name (str): The name of the field in the item to retrieve.

    Returns:
        str: The token retrieved from 1Password, or None if retrieval failed.
    """
    result = subprocess.run(
        ["op", "read", "op://mhammer.pro/GH-PRJ01_gh-depbot-report_finegrain/credential"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        logging.error(f"Failed to get token from 1password: {result.stderr}")  # Log an error
        return None


def arg_parse() -> argparse.Namespace:
    """
    Parses command-line arguments for working with GitHub repositories.

    Parameters:
    None

    Returns:
    argparse.Namespace: The parsed arguments containing action, item_name, item_field, input_file_repos, output_file_repos, and output_file_alerts.
    """
    parser = argparse.ArgumentParser(description="Work with GitHub repositories")
    parser.add_argument('--action', type=str, default="full", help='Action to execute', choices=['full', 'repos', 'repos-alerts', 'org-alerts'])
    parser.add_argument('--item_name_vault', type=str, default="GH-PRJ01_gh-depbot-report_finegrain", help='The name of the Vault item containing the GitHub token')
    parser.add_argument('--item_field_vault', type=str, default="credential", help='The field name in the Vault item containing the GitHub token')
    parser.add_argument('--output_file_prefix', type=str, default="repos.json", help='The base name of the output JSON file for all repositories')
 
    args = parser.parse_args()
    return args


def main():

    start_time = time.time()
    logging.info(f"Start: {start_time}")


    args = arg_parse()
    action = args.action

    headers = get_tokenized_header(args)

    org_dep_alerts = get_organization_dependabot_alerts_gh(headers)
    logging.info(f"Write {len(org_dep_alerts)} dependabot alerts")
    write_json_to_file(org_dep_alerts, "gh_org_dep_alerts.json")

    repos = get_repository_list(args, headers)
    logging.info(f"Write {len(repos)} repos")
    write_json_to_file(repos, "gh_repo_list.json")

    repos_data = get_repository_data_gh(args, headers, repos)
    logging.info(f"Write {len(repos_data)} repos data")
    write_json_to_file(repos_data, "gh_repo_data.json")

    end_time = time.time()

    diff_time = end_time - start_time
    logging.info(f"Duration: {start_time} - {end_time} = {diff_time}")


if __name__ == "__main__":
    main()
