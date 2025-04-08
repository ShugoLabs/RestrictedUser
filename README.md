# Secure Command Execution Framework (SCEF)

### Overview

The Secure Command Execution Framework (SCEF) is an advanced SSH-based access control system for Ubuntu that implements fine-grained command authorization for remote server management. By establishing a controlled execution environment, SCEF enables organizations to grant limited access to critical systems without exposing them to unnecessary risk.

### Architecture  

```
┌─────────────┐     ┌───────────────┐     ┌────────────────┐     ┌────────────────┐
│ SSH Client  │────▶│ ForceCommand  │────▶│ Whitelist      │────▶│ Validated     │    
│             │     │ Wrapper       │     │ Agent          │     │ Command Exec   │
└─────────────┘     └───────────────┘     └────────────────┘     └────────────────┘
                                                 
                                                 │
                                                 ▼
                                          ┌────────────────┐
                                          │ Command        │
                                          │ Authorization  │
                                          │ Database       │
                                          └────────────────┘

```

### Core Components

1. **Restricted Service Account**: Non-interactive system user with locked password authentication.

2. **SSH ForceCommand Directive**: Intercepts all SSH sessions to enforce the whitelist mechanism regardless of what command the client attempts to execute.

3. **Command Whitelist Agent**: 
   - Maintains a declarative list of permitted commands with full paths
   - Performs path normalization and validation
   - Provides comprehensive auditing capabilities

4. **Privilege Escalation Control**: Configures precise sudo permissions to execute only approved commands with elevated privileges.







### Security Features

#### Zero Trust Implementation
SCEF operates on a "never trust, always verify" principle by validating every command against an explicit allowlist, regardless of authentication status.

#### Least Privilege Enforcement
Access is restricted to the minimum set of commands required for operational tasks, with full path specification preventing path manipulation attacks.

#### Command Isolation
The execution environment isolates commands from user input, preventing command chaining, parameter injection, and other shell escaping techniques.

#### Immutable Execution Paths
Script paths are verified against checksums, ensuring that only approved, unmodified scripts can be executed.


### How to Use SCEF in Your Environment  
To integrate **SCEF** into your infrastructure, begin by adapting the setup script to align with your operational policies and security requirements. The script automates the provisioning of a restricted service account, enforces command-level access via SSH, and configures a **whitelist-agent** that permits only explicitly defined commands.
Key customization points include: 
* **User Definition:** Provide the desired restricted username as an argument when running the setup script:
`./scef-setup.sh restricteduser`
* **Command Whitelist:** Tailor the `ALLOWED_COMMANDS` array within the script to match your organization's approved workflows. Each command must include the **full path** and any necessary arguments:
`"/usr/bin/python3.10 /home/restricteduser/scripts/safe_script.py"`
* **Script Paths:** Ensure that referenced scripts are stored in immutable locations with controlled permissions. You can modify the script to support your custom directory structure (e.g., `/opt/tools/secure_ops/`) or implement SHA-Checks on the Client side before Execution.
* **Checksum Enforcement:** Include only verified, hashed scripts in your whitelist. This guarantees integrity and mitigates risks from tampering.
* **SSH Match Rules:** The SSH configuration enforces the use of the whitelist wrapper via the *`ForceCommand`* directive:
```
Match User restricteduser
ForceCommand /usr/local/bin/whitelist-agent-wrapper
```
This section can be extended to support multiple roles by defining different users with tailored `ForceCommand` configurations.

* **Active/Inactive Modes:** Use the provided `whitelist.active.conf` and `whitelist.inactive.conf` files to toggle between strict command enforcement and full shell access (e.g., for maintenance). Just copy the desired config and reload the SSH service:
```
sudo cp /etc/ssh/sshd_config.d/whitelist.active.conf /etc/ssh/sshd_config.d/whitelist.conf
sudo systemctl reload ssh
```
By modularizing access control and centralizing command permissions, SCEF empowers you to implement **Zero Trust access** and **Least Privilege enforcement** with minimal friction and maximum auditability.


### Operational Benefits

#### Centralized Access Management
All permissible commands are defined in a single configuration location, simplifying security audits and compliance reviews.

#### Reduced Attack Surface
By eliminating interactive shell access, the framework dramatically reduces the attack surface available to potential adversaries.

#### Flexible Deployment Models
The framework supports both permanent and temporary whitelist enforcement modes, allowing for maintenance windows with controlled access elevation.

#### Scalability
The design supports extension to multiple service accounts with different command sets, enabling role-based access control patterns.

### Extension Possibilities

#### Management Interface
A web-based UI could be implemented to manage whitelist configurations, providing:
- Visual command set management
- Approval workflows
- Change auditing
- Access reporting

#### SSH Certificate Authority Integration
The framework can be enhanced with an SSH CA to:
- Implement time-bound access certificates
- Enforce multi-factor authentication
- Create principal-based access controls
- Provide centralized key revocation

### Appendix: Mutual Trust Through Checksum Verification

The checksum verification mechanism implements a mutual trust model:

1. **Server-side Validation**: The server verifies that executed scripts match their expected checksums, preventing manipulation of approved scripts.

2. **Client-side Verification**: Users can verify script checksums against a trusted source like github repository before execution, ensuring they are running approved, unmodified code:

```
$ ssh restricteduser@server "/usr/bin/sha256sum /path/to/file.sh"
$ ssh restricteduser@server "/usr/bin/bash /path/to/file.sh"
```

This bilateral verification creates a transparent chain of trust without requiring either party to implicitly trust the execution environment.

                              
