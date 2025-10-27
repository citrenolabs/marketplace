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

from __future__ import annotations

import glob

from soar_sdk.ScriptResult import EXECUTION_STATE_COMPLETED
from soar_sdk.SiemplifyAction import SiemplifyAction
from soar_sdk.SiemplifyUtils import output_handler


@output_handler
def main():
    siemplify = SiemplifyAction()

    folder = siemplify.extract_action_param("Folder", print_value=True)
    is_recursive = siemplify.extract_action_param("Is Recursive", print_value=True)
    file_extension = siemplify.extract_action_param("File Extension")
    files_num = -1

    if not file_extension:
        file_extension = "*.*"
    full_path = folder + "/" + file_extension

    files = glob.glob(full_path, recursive=is_recursive)
    files_num = len(files)

    siemplify.end(files_num, files_num, EXECUTION_STATE_COMPLETED)


if __name__ == "__main__":
    main()
