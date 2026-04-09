"""macOS BPF permission helper — installs a LaunchDaemon to grant packet capture access."""

import grp
import logging
import os
import plistlib
import platform
import shlex
import subprocess

logger = logging.getLogger(__name__)

DAEMON_LABEL = "com.bardsec.pcapdetective.chmodbpf"
DAEMON_PLIST = f"/Library/LaunchDaemons/{DAEMON_LABEL}.plist"
SCRIPT_PATH = "/usr/local/bin/pcap-detective-chmodbpf"
GROUP_NAME = "access_bpf"


def is_macos() -> bool:
    return platform.system() == "Darwin"


def bpf_is_readable() -> bool:
    """Check if the current user can read /dev/bpf0."""
    return os.path.exists("/dev/bpf0") and os.access("/dev/bpf0", os.R_OK | os.W_OK)


def daemon_is_installed() -> bool:
    """Check if the ChmodBPF LaunchDaemon is already installed."""
    return os.path.isfile(DAEMON_PLIST)


def user_in_bpf_group() -> bool:
    """Check if the current user is in the access_bpf group."""
    try:
        bpf_group = grp.getgrnam(GROUP_NAME)
        return os.getlogin() in bpf_group.gr_mem
    except (KeyError, OSError):
        return False


def needs_setup() -> bool:
    """Return True if BPF setup is needed (macOS only)."""
    if not is_macos():
        return False
    return not bpf_is_readable()


def install_bpf_helper() -> tuple[bool, str]:
    """Install the ChmodBPF LaunchDaemon and add the user to access_bpf.

    Prompts for admin credentials via osascript. Returns (success, message).
    """
    if not is_macos():
        return False, "BPF helper is only supported on macOS"

    username = shlex.quote(os.getlogin())

    # Shell script that sets BPF permissions at boot
    script_content = f"""#!/bin/bash
# PCAP Detective — BPF permission helper
# Sets /dev/bpf* readable by the {GROUP_NAME} group at boot.

GROUP="{GROUP_NAME}"

# Create group if it doesn't exist
if ! dscl . -read /Groups/$GROUP &>/dev/null; then
    dseditgroup -o create -q "$GROUP"
fi

# Set permissions on all BPF devices
chgrp "$GROUP" /dev/bpf*
chmod g+rw /dev/bpf*
"""

    # LaunchDaemon plist
    plist_data = {
        "Label": DAEMON_LABEL,
        "ProgramArguments": [SCRIPT_PATH],
        "RunAtLoad": True,
        "StandardErrorPath": "/var/log/pcap-detective-bpf.log",
    }
    plist_bytes = plistlib.dumps(plist_data, fmt=plistlib.FMT_XML)

    # Build the privileged install command
    # We write the script, plist, set permissions, add user to group, and run it
    install_commands = f"""
set -e

# Install the BPF permission script
cat > '{SCRIPT_PATH}' << 'SCRIPTEOF'
{script_content}SCRIPTEOF
chmod 755 '{SCRIPT_PATH}'

# Install the LaunchDaemon plist
cat > '{DAEMON_PLIST}' << 'PLISTEOF'
{plist_bytes.decode()}PLISTEOF
chown root:wheel '{DAEMON_PLIST}'
chmod 644 '{DAEMON_PLIST}'

# Ensure group exists then add user
dseditgroup -o create -q '{GROUP_NAME}' 2>/dev/null || true
dscl . -append /Groups/{GROUP_NAME} GroupMembership '{username}'

# Load the daemon and run it now
launchctl bootout system/{DAEMON_LABEL} 2>/dev/null || true
launchctl bootstrap system '{DAEMON_PLIST}'

# Also run the script immediately so permissions take effect now
'{SCRIPT_PATH}'
"""

    # Use osascript to prompt for admin credentials and run with privileges
    try:
        result = subprocess.run(
            [
                "osascript", "-e",
                f'do shell script "{_escape_applescript(install_commands)}" '
                f'with administrator privileges',
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "User canceled" in stderr or "(-128)" in stderr:
                return False, "Setup was cancelled."
            logger.error(f"BPF helper install failed: {stderr}")
            return False, f"Installation failed: {stderr}"

        # Verify it worked
        if bpf_is_readable():
            return True, "BPF permissions configured successfully. Live capture is ready."
        elif user_in_bpf_group():
            return True, (
                "BPF helper installed. Permissions will take full effect "
                "after signing out and back in (or restarting)."
            )
        else:
            return True, "BPF helper installed. It will take effect on next restart."

    except subprocess.TimeoutExpired:
        return False, "Setup timed out."
    except Exception as e:
        logger.exception("BPF helper install failed")
        return False, f"Setup failed: {e}"


def uninstall_bpf_helper() -> tuple[bool, str]:
    """Remove the ChmodBPF LaunchDaemon and script."""
    if not daemon_is_installed():
        return True, "Nothing to uninstall."

    uninstall_commands = f"""
set -e
launchctl bootout system/{DAEMON_LABEL} 2>/dev/null || true
rm -f '{DAEMON_PLIST}'
rm -f '{SCRIPT_PATH}'
"""

    try:
        result = subprocess.run(
            [
                "osascript", "-e",
                f'do shell script "{_escape_applescript(uninstall_commands)}" '
                f'with administrator privileges',
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if "User canceled" in stderr or "(-128)" in stderr:
                return False, "Uninstall was cancelled."
            return False, f"Uninstall failed: {stderr}"

        return True, "BPF helper removed."

    except Exception as e:
        logger.exception("BPF helper uninstall failed")
        return False, f"Uninstall failed: {e}"


def _escape_applescript(s: str) -> str:
    """Escape a string for embedding inside AppleScript double quotes."""
    return s.replace("\\", "\\\\").replace('"', '\\"')
