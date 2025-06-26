from mcp.server.fastmcp import FastMCP
from oar.core.configstore import ConfigStore
from oar.core.advisory import AdvisoryManager
import logging
import urllib3
import subprocess

# Configure SSL warnings and logging
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("urllib3").setLevel(logging.ERROR)

# Disable SSL warnings for unverified requests
logger = logging.getLogger(__name__)

# Create MCP server with timeout configuration
mcp = FastMCP(name="oar-release-tools", timeout=30)  # 30 second timeout

# Define the is_release_shipped tool
@mcp.tool()
def is_release_shipped(release: str) -> bool:
    """
    Check if all advisories for a release are fully shipped (SHIPPED_LIVE state).
    Logs detailed information about advisory states during checking.
    
    Args:
        release: Release version to check (e.g., "4.12.11")
        
    Returns:
        bool: True if ALL advisories are in SHIPPED_LIVE state, False otherwise
        
    Raises:
        TimeoutError: If the request times out (30s timeout configured)
        Exception: For any other unexpected errors (logged before returning False)
        
    Notes:
        - Uses ConfigStore and AdvisoryManager from oar.core
        - Logs at INFO level for normal operations
        - Logs at ERROR level for failures
    """
    try:
        cs = ConfigStore(release)
        ad_manager = AdvisoryManager(cs)
        advisories = ad_manager.get_advisories()
        
        logger.info(f"Checking if release {release} is shipped")
        
        for advisory in advisories:
            # Get the advisory state
            errata_state = advisory.get_state()
            
            if errata_state != "SHIPPED_LIVE":
                logger.info(f"Advisory {advisory.errata_id} is not in a shipped state (current: {errata_state})")
                return False
                
        logger.info(f"All advisories for release {release} are shipped")
        return True
    except TimeoutError as e:
        logger.error(f"Request timed out while checking release status: {e}")
        return False
    except Exception as e:
        # Log the error
        logger.error(f"Error checking release status: {e}")
        return False



def _execute_cli_command(cmd: list[str]) -> str:
    """
    Shared helper for executing CLI commands with consistent behavior.
    Handles all CLI command execution patterns including:
    - Combined stdout/stderr streams
    - Error handling and logging
    - Timeout management
    - Return value standardization
    
    Args:
        cmd: Complete command and arguments as list
        
    Returns:
        str: Unified output containing either:
             - Command success output (stdout + stderr combined)
             - Formatted error message if execution fails
        
    Raises:
        subprocess.CalledProcessError: For command failures
        Exception: For unexpected execution errors
        
    Notes:
        - Logs execution at INFO level
        - Logs errors at ERROR level
        - Uses check=True to raise on non-zero exit codes
    """
    try:
        logger.info(f"Executing command: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)} - {e.stderr}")
        return f"Command failed: {e.stderr}"
    except Exception as e:
        logger.error(f"Unexpected error executing command: {' '.join(cmd)} - {e}")
        return f"Unexpected error: {e}"

@mcp.tool()
def create_test_report(release: str) -> str:
    """
    Create a release test report via 'oar create-test-report' command.
    
    Args:
        release: Release version (e.g., "4.12.11")
        
    Returns:
        str: Raw output from test report generation
        
    See Also:
        _execute_cli_command() for execution details and error handling
    """
    return _execute_cli_command(["oar", "-r", release, "create-test-report"])

@mcp.tool()
def check_cvp_test_result(release: str) -> str:
    """
    Execute Greenwave CVP test verification via 'oar check-greenwave-cvp-tests'.
    
    Args:
        release: Release version (e.g., "4.12.11")
        
    Returns:
        str: Raw CVP test verification results
        
    See Also:
        _execute_cli_command() for execution details and error handling
    """
    return _execute_cli_command(["oar", "-r", release, "check-greenwave-cvp-tests"])

@mcp.tool()
def check_cve_tracker(release: str, notify: bool = False) -> str:
    """
    Execute CVE tracker bug check via 'oar check-cve-tracker-bug'.
    
    Args:
        release: Release version (e.g., "4.12.11")
        notify: Whether to enable notifications (default: False)
        
    Returns:
        str: Raw output from CVE tracker check
        
    See Also:
        _execute_cli_command() for execution details and error handling
    """
    cmd = ["oar", "-r", release, "check-cve-tracker-bug"]
    if notify:
        cmd.append("--notify")
    else:
        cmd.append("--no-notify")
    return _execute_cli_command(cmd)


# If this file is executed directly, start the server
if __name__ == "__main__":
    # Run the server with the stdio transport for easier testing
    mcp.run(transport='stdio')
