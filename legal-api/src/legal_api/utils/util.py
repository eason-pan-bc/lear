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
# limitations under the License.

"""CORS pre-flight decorator.

A simple decorator to add the options method to a Request Class.
"""
from functools import wraps
from http import HTTPStatus

from legal_api.errors import Error



def cors_preflight(methods: str = 'GET'):
    """Render an option method on the class."""
    def wrapper(func):
        def options(self, *args, **kwargs):  # pylint: disable=unused-argument
            return {'Allow': 'GET'}, 200, \
                   {'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': methods,
                    'Access-Control-Allow-Headers': 'Authorization, Content-Type'}

        setattr(func, 'options', options)
        return func
    return wrapper


def build_schema_error_response(errors):
    """Provide a formatted error response for schema errors."""
    formatted_errors = []
    for error in errors:
        validation_errors = []
        for context in error.context:
            validation_errors.append({
                'message': context.message,
                'jsonPath': context.json_path,
                'validator': context.validator,
                'validatorValue': context.validator_value
            })
        formatted_errors.append({'path': '/'.join(error.path), 'error': error.message, 'context': validation_errors})
    return formatted_errors


def filter_validation_errors(validation_errors, json_data):
    """Filter validation errors to include those related to the absolute path.

    Filters errors based on filing types, header, and business sections.
    """
    if not validation_errors or not json_data:
        return []

    # Get all filing keys to determine what sections exist
    filing_keys = json_data.get('filing', {}).keys()
    # Get the filing items, excluding header and business
    filing_items = [
        filing_item for filing_item in filing_keys
        if filing_item not in ('header', 'business')]

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
            if any(f'filing/{section}' in error_path for section in sections_to_include):
                filtered_errors.append(error)
        # Case 3: Include any other errors without context or with empty context
        else:
            filtered_errors.append(error)

    return filtered_errors if filtered_errors else validation_errors


def handle_uncaught_exceptions(f):
    """Decorator to catch all uncaught exceptions in API endpoints. 

    Return appropriate error responses instead of 500 errors.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            # Execute the endpoint function
            result = f(*args, **kwargs)
            return result
        except KeyError as e:  # Handle uncaught missing fields
            error_msg = [{
                "error": "missing_field",
                "message": f"Field is missing: {str(e)}"
            }]
            return Error(HTTPStatus.BAD_REQUEST, error_msg)
        except Exception as e:  # Catch all other exceptions
            # Determine the error type and message
            msg = []

            # Check for common error patterns to provide better messages
            error_str = str(e).lower()
            if "timeout" in error_str:
                msg.append({
                    "error": "timeout_error",
                    "message": "The operation timed out"
                })
            elif "permission" in error_str or "access" in error_str:
                msg.append({
                    "error": "permission_error",
                    "message": "Permission denied for this operation"
                })
            elif "not found" in error_str:
                msg.append({
                    "error": "not_round_error",
                    "message": "The requested resource was not found"
                })
            else:
                msg.append(e)

            return Error(HTTPStatus.INTERNAL_SERVER_ERROR, msg)

    return decorated
