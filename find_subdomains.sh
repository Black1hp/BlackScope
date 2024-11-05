#!/bin/bash
# ~/.config/subfinder/provider-config.yaml

# Prompt the user for a domain
read -p "Enter the domain to search for subdomains: " domain

# Create a temporary directory for the domain
mkdir -p "$domain"
cd "$domain" || exit

# Run subfinder and save the output
echo "$domain" > domains.txt
subfinder -dL domains.txt -all -recursive -o subfinder_subs.txt

# Run assetfinder and save the output
echo "$domain" | assetfinder --subs-only > assetfinder_subs.txt

# Run amass and save the output
amass enum -passive -d "$domain" -o amass_subs.txt

# Get subdomains from crt.sh using SSL certificates and save to crt_subs.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | \
  jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$' > crt_subs.txt

# Combine, sort, and remove duplicates from all subdomain files
cat subfinder_subs.txt assetfinder_subs.txt amass_subs.txt crt_subs.txt | sort -u > subdomains.txt

# Print the final result
echo "Subdomain discovery complete. Results saved in subdomains.txt."
