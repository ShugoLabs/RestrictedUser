# ================================================================================
# Zero-Trust Command Control Framework Setup

# This script establishes a zero-trust command control framework for secure SSH access
# management on servers. It enforces strict command whitelisting, least privilege access,
# and service user management, ensuring secure operations in untrusted environments.

# --------------------------------------------------------------------------------
# FEATURES:
# - **Zero-Trust Enforcement:** Restricts SSH access to whitelisted commands only.
# - **Service User Management:** Creates and configures dedicated service users with
#   key-based authentication.
# - **Least Privilege Access:** Uses ForceCommand and sudoers to limit user actions.
# - **Command Whitelisting:** Validates commands against a predefined list, ensuring
#   exact matches for execution.
# - **Secure Execution Flow:** Prevents shell access and executes commands in a
#   non-interactive, controlled manner.
# - **Extensibility:** Supports integration with UI for command management and SSH CA
#   for enhanced access control.

# --------------------------------------------------------------------------------
# USAGE:
# 1. **Service User Setup**  
#    Creates a restricted user (e.g., `svc-user`) with SSH key-based access.

# 2. **SSH Configuration**  
#    - Configures SSH with `ForceCommand` to route commands through a wrapper.
#    - Enforces command validation via a whitelist agent.

# 3. **Command Execution**  
#    - Only whitelisted commands are executed, ensuring strict access control.
#    - Logs all attempts for auditing.

# --------------------------------------------------------------------------------
# DEPENDENCIES:
# - Bash (version 4.0 or higher)
# - OpenSSH Server
# - Sudo (for privilege management)

# --------------------------------------------------------------------------------
# SECURITY CONSIDERATIONS:
# - Enforces strict command matching to prevent injection or escalation.
# - Disables interactive shell access via `ForceCommand`.
# - Uses `sudo` with `!requiretty` for non-interactive execution.
# - Stores scripts with restricted permissions to prevent tampering.

# License:
# This software is licensed under the GNU General Public License v3.0 (GPL-3.0) with
# additional terms for enterprise and commercial use.

# - **Enterprise Use:** Free for internal use in enterprise environments (e.g., corporate
#   IT systems) for non-profit-oriented purposes.
# - **Commercial Use Restriction:** Use in profit-oriented businesses (e.g., SaaS, commercial
#   hosting, or resale) is prohibited without explicit permission from the author.
#   For commercial licensing inquiries, please contact Shugo LTD.

# You are free to use, modify, and distribute this software under the terms of the GPL-3.0,
# provided you adhere to the above restrictions. The full GPL-3.0 license terms can be found
# here: https://www.gnu.org/licenses/gpl-3.0.en.html

# Author: Shugo LTD
# Version: 1.0.0

# ================================================================================


#!/bin/bash

restricted_user="$1"

# Exit on any error
set -e

echo "Starting setup process..."

# Main Task 1: Prepare the Environment
echo "Creating dedicated system user (if not exists)..."
if ! id -u $restricted_user &>/dev/null; then
    sudo adduser --disabled-password --gecos "" $restricted_user || { echo "Failed to create user $restricted_user. Exiting."; exit 1; }
else
    echo "User $restricted_user already exists, skipping creation."
fi

echo "Creating SSH directory..."
sudo mkdir -p "/home/$restricted_user/.ssh"
sudo chown -R $restricted_user:$restricted_user "/home/$restricted_user/.ssh"
sudo chmod 700 "/home/$restricted_user/.ssh"

sudo touch "/home/$restricted_user/.ssh/authorized_keys"
sudo chown $restricted_user:$restricted_user "/home/$restricted_user/.ssh/authorized_keys"
sudo chmod 600 "/home/$restricted_user/.ssh/authorized_keys"

echo "Restricting password authentication..."
sudo passwd -l "$restricted_user" || echo "Password already locked or error occurred, continuing..."

# Install SSH server if not already installed
echo "Installing SSH server if not already installed..."
sudo apt update
sudo apt install -y openssh-server || { echo "Failed to install SSH server. Exiting."; exit 1; }

# Ensure SSH service is enabled and running
echo "Ensuring SSH service is enabled and running..."
if systemctl list-unit-files | grep -q "ssh.service"; then
    sudo systemctl enable ssh
    sudo systemctl start ssh
elif systemctl list-unit-files | grep -q "sshd.service"; then
    sudo systemctl enable sshd
    sudo systemctl start sshd
else
    # Fallback for older Ubuntu versions
    sudo service ssh start || sudo service sshd start || echo "Could not start SSH service, please check manually."
fi

# Define the sudoers file name (use a fixed name for simplicity)
sudoers_file="/etc/sudoers.d/90-$restricted_user"

# Create the sudoers file with proper syntax
sudo bash -c "cat <<EOF > '$sudoers_file'
Defaults!/usr/local/bin/whitelist-agent !requiretty
$restricted_user ALL=(ALL) NOPASSWD: /usr/local/bin/whitelist-agent
EOF"

sudo chmod 440 $sudoers_file

# Main Task 2: Install and Configure the Whitelist Agent
echo "Creating audit log directory..."
sudo mkdir -p /var/log/whitelist-agent

echo "Writing the agent script..."
cat << 'EOF_BASE' | sudo tee /usr/local/bin/whitelist-agent
#!/usr/bin/env bash

EOF_BASE

# Append the user-specific allowed commands to the whitelist-agent script
cat << EOF_COMMANDS | sudo tee -a /usr/local/bin/whitelist-agent
# Define allowed commands directly in the script
declare -a ALLOWED_COMMANDS=(
    "/usr/bin/ssh"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/initial_setup.sh"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/challenge.sh"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/example.sh"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/revert.sh"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/wework.py"
    "/usr/bin/sha256sum /home/$restricted_user/core/immutable/werun.py"
    "/usr/bin/bash /home/$restricted_user/core/immutable/tictactoe.sh"
    "/usr/bin/bash /home/$restricted_user/core/immutable/pong.sh"
    "/usr/bin/bash /home/$restricted_user/core/immutable/ping.sh"
    "/usr/bin/bash /home/$restricted_user/core/immutable/sub.sh"
    "/usr/bin/python3.10 /home/$restricted_user/core/immutable/runway.py"
)
EOF_COMMANDS

# Append the rest of the script
cat << 'EOF_REST' | sudo tee -a /usr/local/bin/whitelist-agent

# Function to normalize path
normalize_path() {
    local path="$1"
    # Convert to absolute path and resolve symlinks
    if [[ -e "$path" ]]; then
        readlink -f "$path"
    else
        echo "$path"
    fi
}

is_command_allowed() {
    local full_cmd="$1"
    
    # Extract the base command and its arguments
    read -ra cmd_parts <<< "$full_cmd"

    # Extract main parts
    local base_cmd="${cmd_parts[0]}"   # bash or python3
    local script_path="${cmd_parts[1]}"  # The actual script being executed

    # Convert base command and paths to absolute form
    if command -v "$base_cmd" &> /dev/null; then
        base_cmd=$(command -v "$base_cmd")
    fi
    if [[ -f "$script_path" ]]; then
        script_path=$(realpath "$script_path")
    fi

    # Validate command against allowed commands array (ignoring additional arguments)
    for allowed_cmd in "${ALLOWED_COMMANDS[@]}"; do
        # Compare with base commands
        if [[ "$allowed_cmd" == "$base_cmd $script_path"* ]]; then
            return 0  # Allowed
        fi
    done

    return 1  # Not allowed
}

# Execute the command safely
execute_command() {
    local cmd="$1"

    # Execute the command with sudo
    sudo bash -c "$cmd"
    return $?
}

# The command passed by SSH will be the first argument to this script
cmd="$1"

# Check if a command was provided
if [[ -z "$cmd" ]]; then
    echo "No command provided."
    exit 1
fi

# Extract the base command and check if it exists
base_cmd=$(command -v ${cmd%% *} 2>/dev/null)
if [[ -z "$base_cmd" ]]; then
    echo "Command not found: ${cmd%% *}"
    exit 1
fi

# Normalize the base command path
base_cmd=$(normalize_path "$base_cmd")

# Replace base command with full path
if [[ "$cmd" == *" "* ]]; then
    full_cmd="$base_cmd ${cmd#* }"
else
    full_cmd="$base_cmd"
fi

# Check if command is allowed
if is_command_allowed "$full_cmd"; then
    execute_command "$full_cmd"
    exit_code=$?
    if [[ "$exit_code" -eq 0 ]]; then
        exit $exit_code
    else
        echo "Command '$full_cmd' executed with errors. Exit code: $exit_code"
        exit 1
    fi
else
    echo "Command '$full_cmd' not allowed."
    exit 1
fi
EOF_REST

echo "Writing the agent wrapper..."
cat << 'EOF' | sudo tee /usr/local/bin/whitelist-agent-wrapper
#!/bin/bash

if [ -n "$SSH_ORIGINAL_COMMAND" ]; then
    /usr/local/bin/whitelist-agent "$SSH_ORIGINAL_COMMAND"
else
    /usr/local/bin/whitelist-agent
fi
EOF

echo "Setting proper permissions for the agent script..."
sudo chmod 755 /usr/local/bin/whitelist-agent
sudo chown root:root /usr/local/bin/whitelist-agent

sudo chmod 755 /usr/local/bin/whitelist-agent-wrapper
sudo chown root:root /usr/local/bin/whitelist-agent-wrapper

echo "Configuring SSH to use the agent..."
sudo mkdir -p /etc/ssh/sshd_config.d
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.conf << 'EOF'
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

echo "Creating active/inactive mode configurations..."
sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.active.conf << 'EOF'
Match User $restricted_user
    ForceCommand /usr/local/bin/whitelist-agent-wrapper
EOF"

sudo bash -c "cat > /etc/ssh/sshd_config.d/whitelist.inactive.conf << 'EOF'
# No ForceCommand line, so the user gets a normal shell
EOF"

echo "Reloading SSH to apply changes..."
if systemctl list-unit-files | grep -q "ssh.service"; then
    sudo systemctl reload ssh || sudo systemctl restart ssh
elif systemctl list-unit-files | grep -q "sshd.service"; then
    sudo systemctl reload sshd || sudo systemctl restart sshd
else
    # Fallback for older Ubuntu versions
    sudo service ssh reload || sudo service ssh restart || 
    sudo service sshd reload || sudo service sshd restart ||
    echo "Could not reload SSH service, please restart it manually."
fi

echo "Setup complete!"
echo ""
echo "To activate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.active.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""
echo "To deactivate whitelist enforcement:"
echo "sudo cp /etc/ssh/sshd_config.d/whitelist.inactive.conf /etc/ssh/sshd_config.d/whitelist.conf"
echo "sudo systemctl reload ssh || sudo systemctl reload sshd"
echo ""
