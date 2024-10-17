#!/bin/bash -e

KEYCLOAK_REPO="keycloak/keycloak"
BRANCH_NAME=$(git rev-parse --abbrev-ref HEAD)

# Debug Function to print messages with timestamp
debug() {
  echo "$(date +'%Y-%m-%d %H:%M:%S') - DEBUG - $1"
}

# Extract the version number if BRANCH_NAME contains a slash
debug "Extracting branch version if applicable"
if [[ $BRANCH_NAME == *\/* ]]; then
    BRANCH_NAME=$(echo $BRANCH_NAME | grep -oP '\d+\.\d+')
    debug "Extracted version: $BRANCH_NAME"
fi

# Prevent duplicates by checking if a similar CVE ID exists
check_github_issue_exists() {
    local issue_title="$1"
    debug "Checking if GitHub issue exists for title: $issue_title"
    # Extract the CVE ID
    local CVE_ID=$(echo "$issue_title" | grep -oE '(CVE-[0-9]{4}-[0-9]{4,7}|SNYK-[A-Z]+-[A-Z0-9]+-[0-9]{4,7})')
    debug "Extracted CVE ID: $CVE_ID"
    local search_url="https://api.github.com/search/issues?q=$CVE_ID+is%3Aissue+sort%3Aupdated-desc+repo:$KEYCLOAK_REPO"
    local response=$(curl -f -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" "$search_url")
    debug "GitHub API response: $response"
    local count=$(echo "$response" | jq '.total_count')

    # Check for bad credentials
    if printf "%s" "$response" | jq -e '.message == "Bad credentials"' > /dev/null; then
        printf "Error: Bad credentials\n%s\n" "$response"
        echo "Error: Bad credentials. Aborting script."
        exit 1
    fi

    # Check for rate limiting
    if printf "%s" "$response" | jq -e '.message == "API rate limit exceeded"' > /dev/null; then
        printf "Error: API rate limit exceeded\n%s\n" "$response"
        exit 1
    fi

    # Check if total_count is available
    if [[ $count == "null" ]]; then
        printf "Error: total_count not available in response\n%s\n" "$response"
        exit 1
    fi

    if [[ $count -gt 0 ]]; then
        local issue_id=$(echo "$response" | jq -r '.items[0].number')
        debug "Found existing issue with ID: $issue_id"
        echo "$issue_id"
    else
        debug "No existing issue found"
        echo "1"
    fi
}

# Create a GH issue based on the content of the CVE
create_github_issue() {
    local title="$1"
    local body="$2"
    debug "Creating GitHub issue with title: $title"

    local api_url="https://api.github.com/repos/$KEYCLOAK_REPO/issues"
    local data=$(jq -n --arg title "$title" --arg body "$body" --arg branch "backport/$BRANCH_NAME" \
                 '{title: $title, body: $body, labels: ["status/triage", "kind/cve", "kind/bug", $branch]}')
    debug "Issue data: $data"
    local response=$(curl -f -s -w "%{http_code}" -X POST -H "Authorization: token $GITHUB_TOKEN" -H "Content-Type: application/json" -d "$data" "$api_url")
    debug "GitHub API response: $response"
    local http_code=$(echo "$response" | tail -n1)

    if [[ $http_code -eq 201 ]]; then
        debug "Issue created successfully"
        return 0
    else
        printf "Issue creation failed with status: %s\n" "$http_code"
        exit 1
    fi
}

# Update existing issue based on the branches affected
update_github_issue() {
    local issue_id="$1"
    debug "Updating GitHub issue with ID: $issue_id"
    local api_url="https://api.github.com/repos/$KEYCLOAK_REPO/issues/$issue_id"
    local existing_labels=$(curl -f -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" "$api_url" | jq '.labels | .[].name' | jq -s .)
    debug "Existing labels: $existing_labels"
    local new_label="backport/$BRANCH_NAME"
    local updated_labels=$(echo "$existing_labels" | jq --arg new_label "$new_label" '. + [$new_label] | unique')
    debug "Updated labels: $updated_labels"
    local data=$(jq -n --argjson labels "$updated_labels" '{labels: $labels}')
    debug "Update data: $data"
    local response=$(curl -f -s -w "%{http_code}" -X PATCH -H "Authorization: token $GITHUB_TOKEN" -H "Content-Type: application/json" -d "$data" "$api_url")
    debug "GitHub API response: $response"
    local http_code=$(echo "$response" | tail -n1)

    if [[ $http_code -eq 200 ]]; then
        debug "Issue updated successfully"
        return 0
    else
        printf "Issue update failed with status: %s\n" "$http_code"
        exit 1
    fi
}

check_dependencies() {
    debug "Checking dependencies"
    command -v jq >/dev/null 2>&1 || { echo >&2 "jq is required. Exiting."; exit 1; }
}

# Parse the CVE report coming from SNYK
parse_and_process_vulnerabilities() {
    debug "Parsing and processing vulnerabilities"
    jq -c '.vulnerabilities[] | select(.type != "license")' | while IFS= read -r vulnerability; do
        local cve_title=$(echo "$vulnerability" | jq -r '(.identifiers.CVE[0] // .id) + " - " + (.title // "N/A")')
        local module=$(echo "$vulnerability" | jq -r '((.mavenModuleName.groupId // "unknown") + ":" + (.mavenModuleName.artifactId // "unknown"))')
        local title="${cve_title} in ${module}"
        local from_path=$(echo "$vulnerability" | jq -r 'if .from != [] then "Introduced through: " + (.from | join(" › ")) else "" end')
        local description=$(echo "$vulnerability" | jq -r '.description // "N/A"')

        debug "Processing vulnerability: $title"
        printf -v body "%s\n%s\n%s\n%s" "$title" "$module" "$from_path" "$description"
        issue_id=$(check_github_issue_exists "$cve_title")
        if [[ $issue_id -eq 1 ]]; then
            debug "No existing issue found, creating a new one"
            create_github_issue "$title" "$body"
        else
            debug "Existing issue found, updating issue ID: $issue_id"
            update_github_issue "$issue_id"
        fi
    done
}

main() {
    debug "Starting main function"
    check_dependencies

    if [ -t 0 ]; then
        echo "Error: No input provided. Please pipe in a JSON file."
        echo "Usage: cat snyk-report.json | $0"
        exit 1
    else
        parse_and_process_vulnerabilities
    fi
    debug "Main function finished"
}

main "$@"
