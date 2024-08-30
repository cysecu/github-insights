#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import csv
import json
import logging  # Import the logging module
from datetime import datetime
import xlsxwriter
# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_json_file(filename: str) -> dict:
    """
    Reads a dictionary from a JSON file.

    Parameters:
        filename (str): The path to the JSON file.

    Returns:
        dict: The dictionary read from the JSON file.
    """
    with open(filename, 'r') as f:
        data = json.load(f)
    return data


def get_reduced_alert(alert) -> dict:
    """
    Extracts and returns a reduced dictionary of relevant information from a given alert.

    Parameters:
        alert (dict): The original alert dictionary containing detailed information.

    Returns:
        dict: A reduced dictionary containing key information about the alert.
    """
    alert_rec = {}
    alert_rec["number"] = alert["number"]
    alert_rec["state"] = alert["state"]
    alert_rec["created_at"] = alert["created_at"]
    alert_rec["updated_at"] = alert["updated_at"]
    alert_rec["package"] = alert["dependency"]["package"]["name"]
    alert_rec["ecosystem"] = alert["dependency"]["package"]["ecosystem"]
    alert_rec["scope"] = alert["dependency"]["scope"]
    alert_rec["ghsa_id"] = alert["security_advisory"]["ghsa_id"]
    alert_rec["severity"] = alert["security_vulnerability"]["severity"]
    if "repository" in alert:   # only in organisation alerts
        alert_rec["repository-url"] = alert["repository"]["url"]
    else:
        alert_rec["repository-url"] = alert["url"]

    return alert_rec
    

def get_reduced_org_alerts() -> dict:
    """
    Reads organization dependency alerts from a JSON file, reduces the information to key details,
    and organizes them by repository.

    Returns:
        dict: A dictionary where the keys are repository full names and the values are lists of reduced alert dictionaries.
    """

    gh_org_alerts = read_json_file("gh_org_dep_alerts.json")
    logging.info(f"read {len(gh_org_alerts)} org alerts")
    reduced_org_alerts = {}
    for alert in gh_org_alerts:

        repo_identifier = alert["repository"]["full_name"]
        alert_rec = get_reduced_alert(alert)
        alert_rec["repository-full_name"] = repo_identifier

        repo_container = []
        if(repo_identifier in reduced_org_alerts):
            repo_container = reduced_org_alerts[repo_identifier]
        else:
            reduced_org_alerts[repo_identifier] = repo_container

        repo_container.append(alert_rec)

    return reduced_org_alerts

def get_reduced_repo_data() -> dict:
    """
    Reads repository data from a JSON file, reduces the information to key details,
    and organizes them by repository identifier.

    Returns:
        dict: A dictionary where the keys are repository identifiers and the values are reduced repository data dictionaries.
    """

    gh_repo_data = read_json_file("gh_repo_data.json")
    logging.info(f"read {len(gh_repo_data)} repos")

    reduced_repo_data = {}
    for repo_identifier in gh_repo_data:
        
        repo = gh_repo_data[repo_identifier]
        repo_rec = {}
        repo_rec["full_name"] = repo["full_name"]
        repo_rec["archived"] = repo["archived"]
        repo_rec["disabled"] = repo["disabled"]
        repo_rec["private"] = repo["private"]
        repo_rec["url"] = repo["url"]
        repo_rec["languages"] = repo["languages"]
        
        dep_enabled = repo["dependabot_enabled"]
        repo_rec["dependabot_enabled"] = dep_enabled
       
        repo_alert_container = []
        if dep_enabled:
            for alert in repo["dependabot_alerts"]:
                alert_rec = get_reduced_alert(alert)
                alert_rec["repository-full_name"] = repo_identifier

                repo_alert_container.append(alert_rec)
        else:
            # without dependabot no dependabot alerts
            pass

        repo_rec["dependabot_alerts"] = repo_alert_container

        reduced_repo_data[repo_identifier] = repo_rec
                
    return reduced_repo_data


def create_repo_alerts_vs_org(org_alerts, repos_data):
    """
    Create a comparison of repository alerts versus organization alerts.

    This function generates a CSV-like structure that compares the number of 
    Dependabot alerts for each repository with the number of organization-wide 
    alerts for the same repository.

    Parameters:
        org_alerts (dict): A dictionary containing organization-wide alerts, 
                           where the keys are repository identifiers and the 
                           values are lists of alerts.
        repos_data (dict): A dictionary containing repository data, where the 
                           keys are repository identifiers and the values are 
                           dictionaries with repository details.

    Returns:
        list: A list of lists representing CSV rows. The first row is the header, 
              and subsequent rows contain the comparison data for each repository.
    """

    csv_header = [  "full_name", "archived", \
                    "disabled", "private", "dep_enabled", \
                    "repo_dep_alerts", "org_dep_alerts"
                 ]
    csv_records = []
    csv_records.append(csv_header)
    for repo_key in repos_data:
        repo = repos_data[repo_key]

        logging.info(f"repo: {repo_key}")

        repo_dep_enabled = repo["dependabot_enabled"]
        repo_archived = repo["archived"]
        repo_disabled = repo["disabled"]
        repo_private = repo["private"]

        repo_alert_count = 0
        if(repo["dependabot_alerts"]):
            repo_alert_count =  len(repo["dependabot_alerts"])

        org_alert_count = 0
        if repo_key in org_alerts :
            org_alert_count = len(org_alerts[repo_key])

        csv_record = [  repo_key, repo_archived, \
                        repo_disabled, repo_private, repo_dep_enabled, \
                        repo_alert_count, org_alert_count
                    ]
        csv_records.append(csv_record)

    return csv_records


def get_exist_open_alerts(alerts) -> bool:
    """
    Check if there are any open alerts in the given list of alerts.

    Parameters:
        alerts (list): A list of alert dictionaries, where each dictionary 
                       contains details about an alert, including its state.

    Returns:
        bool: True if there is at least one open alert, False otherwise.
    """
    for alert in alerts:
        if "open" == alert["state"]:
            return True

    return False


def create_gh_overview(repos_data) -> list:
    """
    Generate an overview of GitHub repositories.

    This function creates a CSV-like structure that provides an overview of 
    various repository attributes such as the number of archived repositories, 
    private repositories, repositories with Dependabot enabled, and repositories 
    with Dependabot alerts.

    Parameters:
        repos_data (dict): A dictionary containing repository data, where the 
                           keys are repository identifiers and the values are 
                           dictionaries with repository details.

    Returns:
        list: A list of lists representing CSV rows. The first row is the header, 
              and subsequent rows contain the overview data for each repository.
    """

    counter_number_of_repos = 0
    counter_number_of_repos_archived = 0
    counter_number_of_repos_private = 0
    counter_number_of_repos_dependabot_enabled = 0
    counter_number_of_repos_dependabot_alerts = 0
    counter_number_of_repos_dependabot_alerts_open = 0

    csv_header = ["What", "Case", "Value"]
    csv_records = []
    csv_records.append(csv_header)
    for repo_key in repos_data:
        repo = repos_data[repo_key]

        counter_number_of_repos += 1

        repo_archived = repo["archived"]

        logging.info(f"repo: {repo_key} is archived: {repo_archived}")

        if repo_archived:
            counter_number_of_repos_archived += 1

        elif not repo_archived:

            repo_private = repo["private"]
            if repo_private:
                counter_number_of_repos_private += 1
        
            dep_enabled = repo["dependabot_enabled"]
            if dep_enabled:
                counter_number_of_repos_dependabot_enabled += 1

            if(repo["dependabot_alerts"]):
                repo_alert_count = len(repo["dependabot_alerts"])
                if repo_alert_count > 0:
                    counter_number_of_repos_dependabot_alerts += 1

                if get_exist_open_alerts(repo["dependabot_alerts"]):
                    counter_number_of_repos_dependabot_alerts_open += 1
        else:
            logging.error(f"Unknown Archived State: {repo_archived}")

    csv_record = ["repositories","number of all", counter_number_of_repos]
    csv_records.append(csv_record)

    csv_record = ["repositories","number of archived", counter_number_of_repos_archived]
    csv_records.append(csv_record)

    counter_number_of_repos_active = counter_number_of_repos - counter_number_of_repos_archived
    csv_record = ["repositories","number of active", counter_number_of_repos_active]
    csv_records.append(csv_record)

    csv_record = ["repositories","number of private", counter_number_of_repos_private]
    csv_records.append(csv_record)

    counter_number_of_repos_public = counter_number_of_repos_active - counter_number_of_repos_private
    csv_record = ["repositories","number of public", counter_number_of_repos_public]
    csv_records.append(csv_record)

    csv_record = ["repositories","number of enabled dependabot", counter_number_of_repos_dependabot_enabled]
    csv_records.append(csv_record)

    csv_record = ["repositories","number of repos with dependabot alerts", counter_number_of_repos_dependabot_alerts]
    csv_records.append(csv_record)

    csv_record = ["repositories","number of repos with open dependabot alerts", counter_number_of_repos_dependabot_alerts_open]
    csv_records.append(csv_record)

    return csv_records


def create_gh_repo_short_overview(repos_data) -> list:
    """
    Generate an short overview of GitHub repositories.

    This function creates a CSV-like structure that provides an overview of 
    various repository attributes such as the number of archived repositories, 
    private repositories, repositories with Dependabot enabled, and repositories 
    with Dependabot alerts.

    Parameters:
        repos_data (dict): A dictionary containing repository data, where the 
                           keys are repository identifiers and the values are 
                           dictionaries with repository details.

    Returns:
        list: A list of lists representing CSV rows. The first row is the header, 
              and subsequent rows contain the overview data for each repository.
    """

    csv_header = [  "repo", "private", "dependabot", \
                    "dep_cri_open", "dep_cri_dismissed", "dep_cri_fixed", \
                    "dep_hig_open", "dep_hig_dismissed", "dep_hig_fixed"
                ]
    csv_records = []
    csv_records.append(csv_header)

    for repo_key in repos_data:
        repo = repos_data[repo_key]

        repo_archived = repo["archived"]
        logging.info(f"repo: {repo_key} is archived: {repo_archived}")
        if repo_archived:
            continue

        repo_private = repo["private"]
        repo_dep_enabled = repo["dependabot_enabled"]

        counter_dep_critical_open = 0
        counter_dep_critical_dismissed = 0
        counter_dep_critical_fixed = 0
        counter_dep_high_open = 0
        counter_dep_high_dismissed = 0
        counter_dep_high_fixed = 0

        alerts = repo["dependabot_alerts"]
        for alert in alerts:
            state = alert["state"]
            severity = alert["severity"]
        
            if "open" == state:
                if "critical" == severity:
                    counter_dep_critical_open +=1
                elif "high" == severity:
                    counter_dep_high_open += 1
                else:
                    pass

            elif "fixed" == state:
                
                if "critical" == severity:
                    counter_dep_critical_fixed +=1
                elif "high" == severity:
                    counter_dep_high_fixed += 1
                else:
                    pass
            
            else: #dismissed
                if "critical" == severity:
                    counter_dep_critical_dismissed +=1
                elif "high" == severity:
                    counter_dep_high_dismissed += 1
                else:
                    pass

        csv_record = [  repo_key, repo_private, repo_dep_enabled, \
                        counter_dep_critical_open, counter_dep_critical_dismissed, counter_dep_critical_fixed, \
                        counter_dep_high_open, counter_dep_high_dismissed, counter_dep_high_fixed
                     ]
        csv_records.append(csv_record)

    return csv_records


def create_gh_repo_overview(repos_data) -> list:
    """
    Generate an overview of GitHub repositories.

    This function creates a CSV-like structure that provides an overview of 
    various repository attributes such as the number of archived repositories, 
    private repositories, repositories with Dependabot enabled, and repositories 
    with Dependabot alerts.

    Parameters:
        repos_data (dict): A dictionary containing repository data, where the 
                           keys are repository identifiers and the values are 
                           dictionaries with repository details.

    Returns:
        list: A list of lists representing CSV rows. The first row is the header, 
              and subsequent rows contain the overview data for each repository.
    """

    csv_header = [  "full_name", "private", "dependabot", \
                    "dep_cri_open", "dep_cri_dismissed", "dep_cri_fixed", \
                    "dep_hig_open", "dep_hig_dismissed", "dep_hig_fixed", \
                    "dep_med_open", "dep_med_dismissed", "dep_med_fixed", \
                    "dep_low_open", "dep_low_dismissed", "dep_low_fixed", \
                    "open_cri_max", "open_cri_avg", "open_hig_max", "open_hig_avg"
                ]
    csv_records = []
    csv_records.append(csv_header)

    for repo_key in repos_data:
        repo = repos_data[repo_key]

        repo_archived = repo["archived"]

        logging.info(f"repo: {repo_key} is archived: {repo_archived}")

        if repo_archived:
            continue

        repo_private = repo["private"]
        repo_dep_enabled = repo["dependabot_enabled"]

        counter_dep_critical_open = 0
        counter_dep_critical_dismissed = 0
        counter_dep_critical_fixed = 0
        counter_dep_high_open = 0
        counter_dep_high_dismissed = 0
        counter_dep_high_fixed = 0
        counter_dep_medium_open = 0
        counter_dep_medium_dismissed = 0
        counter_dep_medium_fixed = 0
        counter_dep_low_open = 0
        counter_dep_low_dismissed = 0
        counter_dep_low_fixed = 0
        days_open_critical = []
        days_open_high = []

        alerts = repo["dependabot_alerts"]
        for alert in alerts:
            state = alert["state"]
            created_time = alert["created_at"]
            updated_time = alert["updated_at"]
            severity = alert["severity"]
        
            created_datetime = datetime.strptime(created_time, "%Y-%m-%dT%H:%M:%SZ")
            updated_datetime = datetime.strptime(updated_time, "%Y-%m-%dT%H:%M:%SZ")

            if "open" == state:
                updated_datetime = datetime.utcnow()
                if "critical" == severity:
                    counter_dep_critical_open +=1
                elif "high" == severity:
                    counter_dep_high_open += 1
                elif "medium" == severity:
                    counter_dep_medium_open += 1
                elif "low" == severity:
                    counter_dep_low_open += 1
                else:
                    pass

            elif "fixed" == state:
                
                if "critical" == severity:
                    counter_dep_critical_fixed +=1
                elif "high" == severity:
                    counter_dep_high_fixed += 1
                elif "medium" == severity:
                    counter_dep_medium_fixed += 1
                elif "low" == severity:
                    counter_dep_low_fixed += 1
                else:
                    pass
            
            else: #dismissed
                if "critical" == severity:
                    counter_dep_critical_dismissed +=1
                elif "high" == severity:
                    counter_dep_high_dismissed += 1
                elif "medium" == severity:
                    counter_dep_medium_dismissed += 1
                elif "low" == severity:
                    counter_dep_low_dismissed += 1
                else:
                    pass

            time_diff = updated_datetime - created_datetime
            days_open = round(time_diff.days, 2)
            if "critical" == severity:
                days_open_critical.append(days_open)
            elif "high" == severity:
                days_open_high.append(days_open)

        days_critical = get_max_and_avg_time(days_open_critical)
        days_high = get_max_and_avg_time(days_open_high)

        csv_record = [  repo_key, repo_private, repo_dep_enabled, \
                        counter_dep_critical_open, counter_dep_critical_dismissed, counter_dep_critical_fixed, \
                        counter_dep_high_open, counter_dep_high_dismissed, counter_dep_high_fixed, \
                        counter_dep_medium_open, counter_dep_medium_dismissed, counter_dep_medium_fixed, \
                        counter_dep_low_open, counter_dep_low_dismissed, counter_dep_low_fixed, \
                        days_critical["max"], days_critical["avg"], days_high["max"], days_high["avg"],
                     ]
        csv_records.append(csv_record)

    return csv_records

def create_gh_languages_overview(repos_data) -> list:

    csv_header = [  "full_name", "language" ]
    csv_records = []
    csv_records.append(csv_header)

    for repo_key in repos_data:
        repo = repos_data[repo_key]

        repo_archived = repo["archived"]
        logging.info(f"repo: {repo_key} is archived: {repo_archived}")
        if repo_archived:
            continue

        languages = repo["languages"]
        for language in languages:
            csv_record = [repo_key, language]
            csv_records.append(csv_record)

    return csv_records

def create_gh_languages_summary(repos_data) -> list:

    csv_header = [  "language", "repo_count" ]
    csv_records = []
    csv_records.append(csv_header)

    language_counters = {}
    for repo_key in repos_data:
        repo = repos_data[repo_key]

        repo_archived = repo["archived"]
        logging.info(f"repo: {repo_key} is archived: {repo_archived}")
        if repo_archived:
            continue

        languages = repo["languages"]
        for language in languages:
            language_counter = 0
            if language in language_counters:
                language_counter = language_counters[language]
            
            language_counter += 1
            language_counters[language] = language_counter

    for language in language_counters:
        csv_record = [language, language_counters[language]]
        csv_records.append(csv_record)

    return csv_records

def get_max_and_avg_time( time_list ) -> dict():
    
    item_max = 0
    item_sum = 0
    for item in time_list:
        item_sum += item
        if item > item_max:
            item_max = item

    if len(time_list) > 0:
        item_avg = item_sum / len(time_list)
    else:
        item_avg = 0
 
    return {"max": item_max, "avg": item_avg}

def write_csv_file(output_file, csv_data):
    """
    Write the provided CSV data to a file.

    Parameters:
    output_file (str): The path to the output CSV file.
    csv_data (list of list of str): The CSV data to write, where each inner list represents a row.

    Returns:
    None
    """
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerows(csv_data)

    logging.info(f"CSV data written to {output_file}")

def add_work_sheet(workbook, title, data, header_format):

    worksheet = workbook.add_worksheet(title)
    worksheet.freeze_panes(1, 0)

    row = 0
    for record in data:
        if(row == 0):
            worksheet.write_row(row, 0, record, header_format)
        else:
            worksheet.write_row(row, 0, record)
        row += 1

    return

def main():

    redu_org_alert = get_reduced_org_alerts()
    redu_repo_data = get_reduced_repo_data()

    fileName = "gh_report.xlsx" 
    workbook = xlsxwriter.Workbook(fileName)
    header_format = workbook.add_format(
        {
            "bold": True,
            "align": "center",
            "valign": "vcenter",
            "fg_color": "#D7E4BC",
            "border": 1,
        }
    )

    csv_data = create_gh_overview(redu_repo_data)        
    add_work_sheet(workbook, "Overview", csv_data, header_format)

    csv_data = create_gh_repo_overview(redu_repo_data)    
    add_work_sheet(workbook, "ARepos", csv_data, header_format)

    csv_data = create_gh_repo_short_overview(redu_repo_data)    
    add_work_sheet(workbook, "AReposShort", csv_data, header_format)

    csv_data = create_repo_alerts_vs_org(redu_org_alert, redu_repo_data)
    add_work_sheet(workbook, "CompareOrgVsRepo", csv_data, header_format)

    csv_data = create_gh_languages_overview(redu_repo_data)
    add_work_sheet(workbook, "Languages", csv_data, header_format)

    csv_data = create_gh_languages_summary(redu_repo_data)
    add_work_sheet(workbook, "LanguageSummary", csv_data, header_format)

    # Close the workbook
    workbook.close()


if __name__ == "__main__":
    main()
