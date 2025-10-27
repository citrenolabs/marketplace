# Copyright 2025 Google LLC
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

from mp.core.display_utils import DisplayReport, display_reports
from mp.core.utils import is_github_actions
from mp.validate.data_models import FullReport

from .cli import CliDisplay
from .html.html import HtmlFormat
from .markdown_format import MarkdownFormat


def display_validation_reports(validation_results: FullReport) -> None:
    """Display integrations validation results in various formats.

    This function determines the appropriate display formats (CLI, Markdown, or HTML)
    based on the environment (e.g., GitHub Actions) and then renders the validation reports.

    Args:
        validation_results: A dict that contains the pre-build, build and post-build
        validation results.

    """
    display_types_list: list[DisplayReport] = [CliDisplay(validation_results)]

    if is_github_actions():
        display_types_list.append(MarkdownFormat(validation_results))
    else:
        display_types_list.append(HtmlFormat(validation_results))

    display_reports(*display_types_list)
