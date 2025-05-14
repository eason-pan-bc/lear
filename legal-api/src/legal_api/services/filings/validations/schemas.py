# Copyright © 2019 Province of British Columbia
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License
"""Filings are legal documents that alter the state of a business."""
from http import HTTPStatus
from typing import Dict

from legal_api.errors import Error
from legal_api.schemas import rsbc_schemas
from legal_api.utils.util import build_schema_error_response


def filter_validation_errors(validation_errors, json_data):
    """Filter validation errors to only include those related to the submitted filing types,
    header, and business sections."""
    if not validation_errors or not json_data:
        return []

    # Get all filing keys to determine what sections exist
    filing_keys = json_data.get('filing', {}).keys()
    # Get the filing items, excluding header and business
    filing_items = [filing_item for filing_item in filing_keys 
                   if filing_item != 'header' and filing_item != 'business']
    
    if not filing_items:
        return validation_errors  # Return all errors if no specific filing items

    # Always include header and business sections for validation
    sections_to_include = filing_items + ['header']
    if 'business' in filing_keys:
        sections_to_include.append('business')
    
    # Filter errors to include those related to the submitted filing types, header, and business
    filtered_errors = []
    for error in validation_errors:
        # Case 1: Handle errors with context
        if 'context' in error and error['context']:
            filtered_context = [
                error_detail for error_detail in error['context']
                if any(section in error_detail.get('jsonPath', '') for section in sections_to_include)
            ]
            if filtered_context:
                new_error = error.copy()
                new_error['context'] = filtered_context
                filtered_errors.append(new_error)
        # Case 2: Handle errors with path but empty context (header/business errors)
        elif 'path' in error:
            error_path = error.get('path', '')
            if any(f"filing/{section}" in error_path for section in sections_to_include):
                filtered_errors.append(error)
        # Case 3: Include any other errors without context or with empty context
        else:
            filtered_errors.append(error)
    
    return filtered_errors if filtered_errors else validation_errors


def validate_against_schema(json_data: Dict = None) -> Error:
    """Validate against the filing schema.

    Returns:
        int: status code of the validation operation using HTTPStatus
        List[Dict]: a list of errors defined as {error:message, path:schemaPath}

    """
    valid, err = rsbc_schemas.validate(json_data, 'filing')

    if valid:
        return None

    errors = build_schema_error_response(err)
    errors = filter_validation_errors(errors, json_data)
    return Error(HTTPStatus.UNPROCESSABLE_ENTITY, errors)
