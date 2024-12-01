#!/bin/bash

# Prompt the user for a domain
read -p "Enter the domain to search for subdomains: " domain

# Create a directory for the domain results
mkdir -p "$domain"
cd "$domain" || { echo "Failed to enter directory $domain"; exit 1; }

# Initialize a temporary domains file
echo "$domain" > domains.txt

# Subdomain discovery tools

echo "Running subfinder..."
subfinder -dL domains.txt -all -recursive -o subfinder_subs.txt

echo "Running assetfinder..."
echo "$domain" | assetfinder --subs-only > assetfinder_subs.txt

echo "Running amass..."
amass enum -passive -d "$domain" -o amass_subs.txt

echo "Getting subdomains from crt.sh..."
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\\n/\n/g' | sort -u > crt_subs.txt

# Additional subdomain sources

echo "Getting subdomains from Anubis..."
curl -sk "https://jldc.me/anubis/subdomains/${domain}" | awk -F'"' '{for(i=2;i<NF;i+=2) print $i}' | sort -u > anubis_subs.txt

echo "Getting subdomains from UrlScan..."
curl -sk "https://urlscan.io/api/v1/search/?q=${domain}" | jq -r '.results[].task.domain' | grep -E "\.${domain}$" | sort -u > urlscan_subs.txt

echo "Getting subdomains from AlienVault OTX..."
curl -sk "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" | jq -r '.passive_dns[].hostname' | grep -E "\.${domain}$" | sort -u > otx_subs.txt

# Combine results from all tools, sort, and remove duplicates
echo "Combining and deduplicating results..."
cat subfinder_subs.txt assetfinder_subs.txt amass_subs.txt crt_subs.txt anubis_subs.txt urlscan_subs.txt otx_subs.txt | sort -u > subdomains.txt

# Display the final result
echo "Subdomain discovery complete. Results saved in subdomains.txt."

# Clean up temporary files, keeping only the final output
rm -f domains.txt subfinder_subs.txt assetfinder_subs.txt amass_subs.txt crt_subs.txt anubis_subs.txt urlscan_subs.txt otx_subs.txt

echo "Clean up complete. Only subdomains.txt remains."
