from __future__ import annotations

from typing import TYPE_CHECKING

from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon.extraction import extract_configuration_param

from ..core.constants import INTEGRATION_NAME, PING_SCRIPT_NAME
from ..core.exceptions import JamfError
from ..core.JamfManager import JamfManager

if TYPE_CHECKING:
    from typing import NoReturn


@output_handler
def main() -> NoReturn:
    """
    Test connectivity to Jamf Pro API.

    This action verifies that the integration can successfully authenticate
    and communicate with the Jamf Pro server using the provided credentials.
    """
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    logger = siemplify.LOGGER

    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    # Extract Jamf configuration parameters
    api_root = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="API Root",
        is_mandatory=True,
        print_value=True,
    )
    client_api_id = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client API ID",
        is_mandatory=True,
        print_value=True,
    )
    client_api_secret = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Client API Secret",
        is_mandatory=True,
        print_value=False,
    )
    verify_ssl = extract_configuration_param(
        siemplify,
        provider_name=INTEGRATION_NAME,
        param_name="Verify SSL",
        input_type=bool,
        is_mandatory=False,
        default_value=True,
        print_value=True,
    )
    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""

    try:
        # Initialize Jamf Manager
        manager = JamfManager(
            api_root=api_root,
            client_api_id=client_api_id,
            client_api_secret=client_api_secret,
            verify_ssl=verify_ssl,
            logger=logger,
        )

        # Test connectivity
        manager.test_connectivity()

        output_message = "Successfully connected to Jamf Pro"
        result_value = True
        status = EXECUTION_STATE_COMPLETED

        siemplify.LOGGER.info("Connectivity test passed")

    except JamfError as e:
        siemplify.LOGGER.error(f"Failed to connect to Jamf Pro: {e}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"Failed to connect to Jamf Pro: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result_value}")
    siemplify.LOGGER.info(f"Output: {output_message}")
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
