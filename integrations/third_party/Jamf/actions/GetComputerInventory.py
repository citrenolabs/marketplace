from ScriptResult import EXECUTION_STATE_COMPLETED, EXECUTION_STATE_FAILED
from SiemplifyAction import SiemplifyAction
from SiemplifyUtils import output_handler
from TIPCommon.extraction import extract_configuration_param, extract_action_param

from constants import INTEGRATION_NAME, GET_COMPUTER_INVENTORY_SCRIPT_NAME
from exceptions import JamfError
from JamfManager import JamfManager


@output_handler
def main():
    """
    Retrieve computer inventory from Jamf Pro with pagination and filtering support.

    This action retrieves computer inventory data from Jamf Pro with support for
    pagination, sorting, filtering, and section selection to optimize data retrieval.
    """
    siemplify = SiemplifyAction()
    siemplify.script_name = GET_COMPUTER_INVENTORY_SCRIPT_NAME
    siemplify.LOGGER.info("----------------- Main - Param Init -----------------")

    status = EXECUTION_STATE_COMPLETED
    output_message = ""
    result_value = False

    try:
        # INIT INTEGRATION CONFIGURATION:
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
            is_mandatory=True,
            default_value=True,
            print_value=True,
        )

        # EXTRACT ACTION PARAMETERS:
        page = extract_action_param(
            siemplify,
            param_name="Page",
            is_mandatory=False,
            print_value=True,
            default_value="0",
        )
        page_size = extract_action_param(
            siemplify,
            param_name="Page Size",
            is_mandatory=False,
            print_value=True,
            default_value="100",
        )
        sort_criteria = extract_action_param(
            siemplify,
            param_name="Sort",
            is_mandatory=False,
            print_value=True,
            default_value="",
        )
        filter_criteria = extract_action_param(
            siemplify,
            param_name="Filter",
            is_mandatory=False,
            print_value=True,
            default_value="",
        )
        section_criteria = extract_action_param(
            siemplify,
            param_name="Section",
            is_mandatory=False,
            print_value=True,
            default_value="",
        )

        # Convert and validate parameters
        try:
            page = int(page)
            page_size = int(page_size)
        except ValueError:
            raise JamfError("Page and Page Size must be valid integers")

        if page < 0:
            raise JamfError("Page number must be 0 or greater")
        if page_size < 1:
            raise Exception("Page size must be greater than 0")

        # Convert list parameters to API-compatible strings
        sort_string = None
        if sort_criteria and isinstance(sort_criteria, list) and len(sort_criteria) > 0:
            sort_string = ",".join([str(item) for item in sort_criteria if item])
            siemplify.LOGGER.info(f"Sort criteria converted: {sort_string}")
        elif sort_criteria and isinstance(sort_criteria, str) and sort_criteria.strip():
            # Check for JSON representations of empty arrays or null values
            stripped_sort = sort_criteria.strip()
            if stripped_sort in ["[]", "[null]", "null", ""]:
                sort_string = None  # Don't send sort parameter
                siemplify.LOGGER.info("Sort criteria is empty, omitting sort parameter")
            else:
                # Try to parse JSON array if it looks like one
                if stripped_sort.startswith("[") and stripped_sort.endswith("]"):
                    try:
                        import json

                        parsed = json.loads(stripped_sort)
                        if isinstance(parsed, list) and len(parsed) > 0:
                            sort_string = ",".join([str(item) for item in parsed if item])
                        else:
                            sort_string = None
                    except (json.JSONDecodeError, ValueError):
                        # Treat as single value
                        sort_string = stripped_sort
                else:
                    # Single value
                    sort_string = stripped_sort
                siemplify.LOGGER.info(f"Sort criteria processed: {sort_string}")

        filter_string = None
        if filter_criteria and isinstance(filter_criteria, list) and len(filter_criteria) > 0:
            filter_string = " and ".join(filter_criteria)  # Jamf API uses 'and' to combine filters
            siemplify.LOGGER.info(f"Filter criteria converted: {filter_string}")
        elif filter_criteria and isinstance(filter_criteria, str) and filter_criteria.strip():
            # Check for JSON representations of empty arrays or null values
            stripped_filter = filter_criteria.strip()
            if stripped_filter in ["[]", "[null]", "null", ""]:
                filter_string = None  # Don't send filter parameter
                siemplify.LOGGER.info("Filter criteria is empty, omitting filter parameter")
            else:
                filter_string = stripped_filter
                siemplify.LOGGER.info(f"Filter criteria processed: {filter_string}")

        section_string = None
        if section_criteria and isinstance(section_criteria, list) and len(section_criteria) > 0:
            # Convert to uppercase and join with commas
            section_string = ",".join([str(item).upper() for item in section_criteria if item])
            siemplify.LOGGER.info(f"Section criteria converted: {section_string}")
        elif section_criteria and isinstance(section_criteria, str) and section_criteria.strip():
            # Check for JSON representations of empty arrays or null values
            stripped_section = section_criteria.strip()
            if stripped_section in ["[]", "[null]", "null", ""]:
                section_string = None  # Don't send section parameter
                siemplify.LOGGER.info("Section criteria is empty, omitting section parameter")
            else:
                # Try to parse JSON array if it looks like one
                if stripped_section.startswith("[") and stripped_section.endswith("]"):
                    try:
                        import json

                        parsed = json.loads(stripped_section)
                        if isinstance(parsed, list) and len(parsed) > 0:
                            # Convert to uppercase and join with commas
                            section_string = ",".join([
                                str(item).upper() for item in parsed if item
                            ])
                        else:
                            section_string = None
                    except (json.JSONDecodeError, ValueError):
                        # Treat as single value, convert to uppercase
                        section_string = stripped_section.upper()
                else:
                    # Single value, convert to uppercase
                    section_string = stripped_section.upper()
                siemplify.LOGGER.info(f"Section criteria processed: {section_string}")

        siemplify.LOGGER.info(
            f"Starting Get Computer Inventory action - Page: {page}, Page Size: {page_size}"
        )
        siemplify.LOGGER.info(
            f"Sort: {sort_string}, Filter: {filter_string}, Section: {section_string}"
        )

        # Initialize Jamf Manager
        jamf_manager = JamfManager(
            api_root=api_root,
            client_api_id=client_api_id,
            client_api_secret=client_api_secret,
            verify_ssl=verify_ssl,
            logger=siemplify.LOGGER,
        )

        siemplify.LOGGER.info(f"Retrieving computer inventory - Page: {page}, Size: {page_size}")

        # Retrieve computer inventory
        inventory_data = jamf_manager.get_computer_inventory(
            page=page,
            page_size=page_size,
            sort=sort_string,
            filter=filter_string,
            section=section_string,
        )

        if inventory_data:
            # Extract inventory information
            results = inventory_data.get("results", [])
            total_count = inventory_data.get("totalCount", 0)
            results_count = len(results)

            # Calculate pagination info
            has_more_pages = (page + 1) * page_size < total_count

            # Prepare comprehensive result
            json_result = {
                "page": page,
                "page_size": page_size,
                "sort_criteria": sort_string,
                "filter_criteria": filter_string,
                "sections_requested": section_string,
                "inventory_data": inventory_data,
            }

            siemplify.result.add_result_json(json_result)

            # Create detailed output message
            output_parts = [
                f"Successfully retrieved {results_count} computers from inventory (total: {total_count})"
            ]

            if sort_string:
                output_parts.append(f"Sorted by: {sort_string}")
            if filter_string:
                output_parts.append(f"Filtered by: {filter_string}")
            if section_string:
                output_parts.append(f"Sections: {section_string}")
            if has_more_pages:
                output_parts.append(f"More pages available (current page: {page})")

            output_message = ". ".join(output_parts)
            result_value = True
            status = EXECUTION_STATE_COMPLETED

        else:
            siemplify.LOGGER.info("No computer inventory data found")
            json_result = {"inventory_data": None, "summary": {"results_count": 0}}
            siemplify.result.add_result_json(json_result)
            output_message = "No computer inventory data found"
            result_value = True  # Still successful, just empty results

    except JamfError as e:
        siemplify.LOGGER.error(f"Jamf API error while retrieving computer inventory: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"Jamf API error: {e}"
        result_value = False

    except Exception as e:
        siemplify.LOGGER.error(f"Unexpected error while retrieving computer inventory: {e}")
        siemplify.LOGGER.exception(e)
        status = EXECUTION_STATE_FAILED
        output_message = f"Unexpected error: {str(e)}"
        result_value = False

    siemplify.LOGGER.info("----------------- Main - Finished -----------------")
    siemplify.LOGGER.info(f"Status: {status}")
    siemplify.LOGGER.info(f"Result: {result_value}")
    siemplify.LOGGER.info(f"Output: {output_message}")

    siemplify.end(output_message, result_value, status)


if __name__ == "__main__":
    main()
