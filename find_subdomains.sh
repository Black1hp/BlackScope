#!/bin/bash

# Function to perform subdomain discovery for a given domain
perform_subdomain_discovery() {
    local domain="$1"
    
    echo "Starting subdomain discovery for: $domain"
    
    # Create a directory for the domain results
    mkdir -p "$domain"
    cd "$domain" || { echo "Failed to enter directory $domain"; return 1; }

    # Initialize a temporary domains file
    echo "$domain" > domains.txt

    # Run subdomain discovery tools
    echo "Running subfinder..."
    subfinder -dL domains.txt -all -recursive -o subfinder_subs.txt 2>/dev/null

    echo "Running assetfinder..."
    echo "$domain" | assetfinder --subs-only > assetfinder_subs.txt 2>/dev/null

    echo "Running amass..."
    amass enum -passive -d "$domain" -o amass_subs.txt 2>/dev/null

    echo "Getting subdomains from crt.sh..."
    curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\\n/\n/g' | sort -u > crt_subs.txt 2>/dev/null

    # Additional subdomain sources
    echo "Getting subdomains from Anubis..."
    curl -sk "https://jldc.me/anubis/subdomains/${domain}" | awk -F'"' '{for(i=2;i<NF;i+=2) print $i}' | sort -u > anubis_subs.txt 2>/dev/null

    echo "Getting subdomains from UrlScan..."
    curl -sk "https://urlscan.io/api/v1/search/?q=${domain}" | jq -r '.results[].task.domain' | grep -E "\.${domain}$" | sort -u > urlscan_subs.txt 2>/dev/null

    echo "Getting subdomains from AlienVault OTX..."
    curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" | jq -r '.passive_dns[].hostname' | grep -E "\.${domain}$" | sort -u > otx_subs.txt 2>/dev/null

    # Combine results from all tools, sort, and remove duplicates
    echo "Combining and deduplicating results..."
    cat subfinder_subs.txt assetfinder_subs.txt amass_subs.txt crt_subs.txt anubis_subs.txt urlscan_subs.txt otx_subs.txt | sort -u > subdomains_raw.txt

    # Filter out damaged subdomains and save to the final output file
    grep -v "^\*\." subdomains_raw.txt > subdomains.txt

    # Display the final result
    echo "Subdomain discovery complete for $domain. Results saved in $domain/subdomains.txt."

    # Clean up temporary files, keeping only the final output
    rm -f domains.txt subfinder_subs.txt assetfinder_subs.txt amass_subs.txt crt_subs.txt anubis_subs.txt urlscan_subs.txt otx_subs.txt subdomains_raw.txt

    cd .. || echo "Failed to return to parent directory."
}

# Main script starts here

# Prompt the user for input
read -p "Enter the name of the file containing domains (or press Enter to run on a single domain): " file_name

if [[ -n "$file_name" ]]; then
    # If a file is provided, check if it exists
    if [[ ! -f "$file_name" ]]; then
        echo "Error: File '$file_name' does not exist."
        exit 1
    fi

    # Read each domain from the file and run the script
    while IFS= read -r domain; do
        if [[ -n "$domain" ]]; then
            perform_subdomain_discovery "$domain"
        else
            echo "Skipped empty line in file."
        fi
    done < "$file_name"
else
    # If no file is provided, prompt for a single domain
    read -p "Enter the domain to search for subdomains: " domain

    if [[ -z "$domain" ]]; then
        echo "Error: No domain provided."
        exit 1
    fi

    perform_subdomain_discovery "$domain"
fi

echo "Script execution complete."
