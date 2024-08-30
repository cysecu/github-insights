"""
GitHub Analyzer Package

This package provides functionality to interact with GitHub repositories, fetch various details, and analyze the fetched data.

Modules:
- get_gh_data: Contains functions to fetch and process GitHub repository data.
- analyse_gh_data: Contains functions to analyze the fetched GitHub repository data.
- utils: Contains utility functions for reading and writing JSON files, and handling logging.

Usage:
    import get_gh_data
    import analyse_gh_data
    import utils

    # Example usage
    args = get_gh_data.arg_parse()
    headers = get_gh_data.get_tokized_header(args)
    repos = get_gh_data.get_repository_list(args, headers)
    utils.write_json_to_file(repos, "gh_repo_list.json")
"""
