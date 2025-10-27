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

from soar_sdk.SiemplifyJob import SiemplifyJob
from soar_sdk.SiemplifyUtils import output_handler

from ..core.definitions import VisualFamily
from ..core.GitSyncManager import GitSyncManager

SCRIPT_NAME = "Push Custom Family"


@output_handler
def main():
    siemplify = SiemplifyJob()
    siemplify.script_name = SCRIPT_NAME

    commit_msg = siemplify.extract_job_param("Commit")
    family_names = [
        _f
        for _f in [
            x.strip()
            for x in siemplify.extract_job_param("Family Name", " ").split(",")
        ]
        if _f
    ]
    readme_addon = siemplify.extract_job_param("Readme Addon", input_type=str)

    try:
        gitsync = GitSyncManager.from_siemplify_object(siemplify)

        for visualFamily in gitsync.api.get_custom_families():
            if visualFamily["family"] in family_names:
                if readme_addon:
                    siemplify.LOGGER.info(
                        "Readme addon found - adding to GitSync metadata file (GitSync.json)",
                    )
                    gitsync.content.metadata.set_readme_addon(
                        "Visual Family",
                        visualFamily.get("family"),
                        readme_addon,
                    )

                siemplify.LOGGER.info(
                    f"Pushing Visual Family - {visualFamily.get('family')}",
                )
                gitsync.content.push_visual_family(
                    VisualFamily(gitsync.api.get_custom_family(visualFamily["id"])),
                )

        gitsync.commit_and_push(commit_msg)

    except Exception as e:
        siemplify.LOGGER.error(f"General error performing Job {SCRIPT_NAME}")
        siemplify.LOGGER.exception(e)
        raise


if __name__ == "__main__":
    main()
