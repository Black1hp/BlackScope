#!/bin/bash

# Function to check if a command exists
command_exists () {
  command -v "$1" >/dev/null 2>&1
}

# Install Go
if ! command_exists go; then
  echo "Go not found. Installing Go..."
  wget https://go.dev/dl/go1.24.6.linux-amd64.tar.gz
  sudo rm -rf /usr/local/go
  sudo tar -C /usr/local -xzf go1.24.6.linux-amd64.tar.gz
  rm go1.24.6.linux-amd64.tar.gz
  echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
  source ~/.profile
  echo "Go installed."
else
  echo "Go is already installed."
fi

# Update PATH for current session
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# Install system dependencies
echo "Installing system dependencies (jq, git, python3-pip, cargo)..."
sudo apt-get update
sudo apt-get install -y jq git python3-pip cargo
echo "System dependencies installed."

# Clone BlackScope
if [ ! -d "BlackScope" ]; then
  echo "Cloning BlackScope repository..."
  git clone https://github.com/Black1hp/BlackScope.git
  echo "BlackScope repository cloned."
else
  echo "BlackScope repository already exists."
fi

# Install Go-based tools
GO_TOOLS=("subfinder" "amass" "assetfinder" "ffuf" "dnsx")
for tool in "${GO_TOOLS[@]}"; do
  if ! command_exists "$tool"; then
    echo "Installing $tool..."
    go install -v github.com/projectdiscovery/${tool}/v2/cmd/${tool}@latest || \
    go install -v github.com/owasp-amass/${tool}/v4/...@master || \
    go install -v github.com/tomnomnom/${tool}@latest || \
    go install -v github.com/ffuf/${tool}@latest || \
    go install -v github.com/projectdiscovery/${tool}/cmd/${tool}@latest
    echo "$tool installed."
  else
    echo "$tool is already installed."
  fi
done

# Install findomain
if ! command_exists findomain; then
  echo "Installing findomain..."
  wget https://github.com/Findomain/Findomain/releases/download/10.0.1/findomain-linux.zip
  unzip findomain-linux.zip
  sudo mv findomain /usr/local/bin/findomain
  sudo chmod +x /usr/local/bin/findomain
  rm findomain-linux.zip
  echo "findomain installed."
else
  echo "findomain is already installed."
fi

# Install Sublist3r
if [ ! -d "~/black1hp/Sublist3r" ]; then
  echo "Cloning Sublist3r repository..."
  git clone https://github.com/aboul3la/Sublist3r.git ~/black1hp/Sublist3r
  echo "Sublist3r repository cloned."
fi

if [ -f "~/black1hp/Sublist3r/requirements.txt" ]; then
  echo "Installing Sublist3r Python dependencies..."
  pip3 install -r ~/black1hp/Sublist3r/requirements.txt
  echo "Sublist3r Python dependencies installed."
fi

# Install dnscan
if [ ! -d "~/black1hp/dnscan" ]; then
  echo "Cloning dnscan repository..."
  git clone https://github.com/rbsec/dnscan.git ~/black1hp/dnscan
  echo "dnscan repository cloned."
fi

if [ -f "~/black1hp/dnscan/requirements.txt" ]; then
  echo "Installing dnscan Python dependencies..."
  pip3 install -r ~/black1hp/dnscan/requirements.txt
  echo "dnscan Python dependencies installed."
fi

# Install dnsgen
if ! command_exists dnsgen; then
  echo "Installing dnsgen..."
  pip3 install dnsgen
  echo "dnsgen installed."
else
  echo "dnsgen is already installed."
fi

# Set Up Wordlist
if [ ! -d "~/SecLists" ]; then
  echo "Cloning SecLists repository..."
  git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
  echo "SecLists repository cloned."
else
  echo "SecLists repository already exists."
fi

echo "BlackScope setup complete!"


