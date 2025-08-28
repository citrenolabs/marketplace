from SiemplifyAction import SiemplifyAction
from StairwellManager import StairwellManager
from SiemplifyUtils import output_handler
from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED, EXECUTION_STATE_TIMEDOUT
from TIPCommon.extraction import extract_configuration_param
from constants import PING_SCRIPT_NAME, INTEGRATION_NAME


@output_handler
def main():
    siemplify = SiemplifyAction()
    siemplify.script_name = PING_SCRIPT_NAME
    logger = siemplify.LOGGER
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    api_root = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="API Root", is_mandatory=True
    )
    api_key = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="API Key", is_mandatory=True
    )
    org_id = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="Organization ID", is_mandatory=False
    )
    user_id = extract_configuration_param(
        siemplify, provider_name=INTEGRATION_NAME, param_name="User ID", is_mandatory=False
    )

    siemplify.LOGGER.info("----------------- Main - Started -----------------")

    status = EXECUTION_STATE_COMPLETED
    result_value = True
    output_message = ""

    try:
        manager = StairwellManager(
            api_key=api_key, org_id=org_id, user_id=user_id, logger=logger, api_root=api_root
        )
        status = EXECUTION_STATE_COMPLETED
        manager.test_connectivity()
        output_message = "Connection Established"
        result_value = True
        siemplify.LOGGER.info("Finished processing")

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing action {PING_SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        result_value = False
        status = EXECUTION_STATE_FAILED
        output_message = f"An error occurred while running action: {e}"

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(
        f"\n  status: {status}\n  is_success: {result_value}\n  output_message: {output_message}"
    )
    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
