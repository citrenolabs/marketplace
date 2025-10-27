"""Module for interacting with the operating system and executing shell commands."""

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

import pathlib
import subprocess as sp  # noqa: S404
import sys
from typing import IO, TYPE_CHECKING

import rich

from mp.core.exceptions import FatalValidationError, NonFatalValidationError
from mp.core.utils import is_windows

from . import config, constants, file_utils

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

COMMAND_ERR_MSG: str = "Error happened while executing a command: {0}"


class FatalCommandError(FatalValidationError):
    """Fatal error that happens during commands."""


class NonFatalCommandError(NonFatalValidationError):
    """Non-fatal error that happens during shell commands."""


def compile_core_integration_dependencies(
    project_path: pathlib.Path,
    requirements_path: pathlib.Path,
) -> None:
    """Compile/Export all project dependencies into a requirements' file.

    Args:
        project_path: the path to the project folder - one that contains a
            `pyproject.toml` file
        requirements_path: the path to the requirements' file to write the contents into

    Raises:
        FatalCommandError: if a project is already initialized

    """
    python_version: str = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    command: list[str] = [
        sys.executable,
        "-m",
        "uv",
        "export",
        "--project",
        str(project_path),
        "--output-file",
        str(requirements_path),
        "--no-hashes",
        "--no-dev",
        "--python",
        python_version,
    ]
    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        sp.run(command, cwd=project_path, check=True, text=True)  # noqa: S603
    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def _get_safe_to_ignore_packages(e: sp.CalledProcessError, /) -> list[str]:
    full_msg: str = f"{e.stdout or ''}\n{e.stderr or ''}"
    ignored_packages: list[str] = [
        pkg for pkg in constants.SAFE_TO_IGNORE_PACKAGES if pkg in full_msg
    ]
    ignored_messages: list[bool] = [
        msg in full_msg for msg in constants.SAFE_TO_IGNORE_ERROR_MESSAGES
    ]
    if ignored_messages and ignored_packages:
        return ignored_packages
    return []


def run_pip_command(command: list[str], cwd: pathlib.Path) -> None:
    """Run a pip command and ignore safe-to-ignore errors.

    Raises:
        FatalCommandError: if a pip command fails.

    """
    try:
        sp.run(command, cwd=cwd, capture_output=True, text=True, check=True)  # noqa: S603
    except sp.CalledProcessError as e:
        # Check if this is a safe-to-ignore error / marker issue
        if ignored_packages := _get_safe_to_ignore_packages(e):
            message = (
                f"[INFO] Ignored safe-to-ignore packages due to Python version "
                f"incompatibility: {', '.join(ignored_packages)}\n"
            )
            rich.print(message)
            return
        raise FatalCommandError from e


def download_wheels_from_requirements(
    project_path: pathlib.Path,
    requirements_path: pathlib.Path,
    dst_path: pathlib.Path,
) -> None:
    """Download `.whl` files from a requirements' file.

    Args:
        project_path: the path of the project repository
        requirements_path: the path of the 'requirements.txt' file
        dst_path: the path to install the `.whl` files into

    Raises:
        FatalCommandError: if a project is already initialized

    """
    python_version: str = _get_python_version()
    command: list[str] = [
        sys.executable,
        "-m",
        "pip",
        "download",
        "-r",
        str(requirements_path),
        "-d",
        str(dst_path),
        "--only-binary=:all:",
        "--python-version",
        python_version,
        "--implementation",
        "cp",
        "--platform",
        "none-any",
    ]
    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        platform: str = "win_amd64" if is_windows() else "manylinux_2_17_x86_64"
        command.extend(["--platform", platform])
        run_pip_command(command, cwd=project_path)
    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def add_dependencies_to_toml(
    project_path: pathlib.Path,
    requirements_path: pathlib.Path,
) -> None:
    """Add dependencies from requirements to a python project's TOML file.

    Args:
        project_path: the path to the project
        requirements_path: the path to the requirements to add

    Raises:
        FatalCommandError: if a project is already initialized

    """
    python_version: str = _get_python_version()
    command: list[str] = [
        sys.executable,
        "-m",
        "uv",
        "add",
        "-r",
        str(requirements_path),
        "--python",
        python_version,
    ]
    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        sp.run(command, cwd=project_path, check=True, text=True)  # noqa: S603
    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def init_python_project_if_not_exists(project_path: pathlib.Path) -> None:
    """Initialize a python project in a folder.

    If a project is already initialized in there, nothing will happen.

    Args:
        project_path: the path to initialize the project

    """
    pyproject: pathlib.Path = project_path / constants.PROJECT_FILE
    if pyproject.exists():
        return

    initials: set[pathlib.Path] = set(project_path.iterdir())
    keep: set[pathlib.Path] = {
        project_path / constants.PROJECT_FILE,
        project_path / constants.LOCK_FILE,
    }

    init_python_project(project_path)

    paths: set[pathlib.Path] = set(project_path.iterdir())
    paths_to_remove: set[pathlib.Path] = paths.difference(initials).difference(keep)
    file_utils.remove_paths_if_exists(*paths_to_remove)


def init_python_project(project_path: pathlib.Path) -> None:
    """Initialize a python project in a folder.

    Args:
        project_path: the path to initialize the project

    Raises:
        FatalCommandError: if a project is already initialized

    """
    python_version: str = _get_python_version()
    command: list[str] = [
        sys.executable,
        "-m",
        "uv",
        "init",
        "--no-readme",
        "--no-workspace",
        "--python",
        python_version,
    ]

    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        sp.run(command, cwd=project_path, check=True, text=True)  # noqa: S603
    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def ruff_check(paths: Iterable[pathlib.Path], /, **flags: bool | str) -> int:
    """Run `ruff check` on the provided paths.

    Returns:
        The status code

    """
    command: list[str] = [sys.executable, "-m", "ruff", "check"]
    return execute_command_and_get_output(command, paths, **flags)


def ruff_format(paths: Iterable[pathlib.Path], /, **flags: bool | str) -> int:
    """Run `ruff format` on the provided paths.

    Returns:
        The status code

    """
    command: list[str] = [sys.executable, "-m", "ruff", "format"]
    return execute_command_and_get_output(command, paths, **flags)


def mypy(paths: Iterable[pathlib.Path], /, **flags: bool | str) -> int:
    """Run `mypy` on the provided paths.

    Returns:
        The status code

    """
    command: list[str] = [sys.executable, "-m", "mypy"]
    return execute_command_and_get_output(command, paths, **flags)


def run_script_on_paths(
    script_path: pathlib.Path,
    *test_paths: pathlib.Path,
) -> int:
    """Run a custom script on the provided paths.

    Returns:
        The status code of the output

    """
    script_full_path: str = f"{script_path.resolve().absolute()}"

    if not sys.platform.startswith("win"):
        chmod_command: list[str] = ["chmod", "+x", script_full_path]
        sp.run(chmod_command, check=True)  # noqa: S603

    command: list[str] = [script_full_path] + [str(p) for p in test_paths]

    result = sp.run(  # noqa: S603
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    return result.returncode


def execute_command_and_get_output(
    command: list[str],
    paths: Iterable[pathlib.Path],
    **flags: bool | str,
) -> int:
    """Execute a command and capture its output and status code.

    Args:
        command: the command values to execute
        paths: path values for the command
        **flags: any command flags as keyword arguments

    Returns:
        The status code of the process

    Raises:
        FatalCommandError: if a project is already initialized

    """
    command.extend(str(path) for path in paths)

    flags_: list[str] = get_flags_to_command(**flags)
    command.extend(flags_)

    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        process: sp.Popen[bytes] = sp.Popen(command)  # noqa: S603
        for line in _stream_process_output(process):
            rich.print(str(line))
        return process.wait()

    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def _stream_process_output(process: sp.Popen[bytes]) -> Iterator[bytes]:
    buffer: IO[bytes] | None = process.stdout
    if process.stdout is None:
        buffer = process.stderr

    if buffer is None:
        return

    line: bytes = buffer.readline()
    while line:
        yield line
        line = buffer.readline()


def get_changed_files() -> list[str]:
    """Get a list of file names that were changed since the last commit.

    Returns:
        A list of file names that were changed since the last commit.

    Raises:
        FatalCommandError: The command failed to be executed

    """
    command: list[str] = [
        "git",
        "diff",
        "HEAD^",
        "HEAD",
        "--name-only",
        "--diff-filter=ACMRTUXB",
    ]
    try:
        result: sp.CompletedProcess[str] = sp.run(  # noqa: S603
            command,
            check=True,
            text=True,
            capture_output=True,
        )
        return result.stdout.split()

    except sp.CalledProcessError as e:
        raise FatalCommandError(COMMAND_ERR_MSG.format(e)) from e


def _get_runtime_config() -> list[str]:
    result: list[str] = []
    if config.is_quiet():
        result.append("--quiet")

    if config.is_verbose():
        result.append("--verbose")

    return result


def get_flags_to_command(**flags: bool | str | list[str]) -> list[str]:
    """Get all the kwarg flags as a string with the appropriate `-` or `--`.

    Examples:
        >>> get_flags_to_command(f=True, name="TIPCommon", files=["1", "2"])
        >>> "-f --name TIPCommon --files 1 2"

    Keyword Args:
        **flags: The flags to parse

    Returns:
        A string containing the flags for a command.

    """
    if not flags:
        return []

    all_flags: list[str] = []
    for flag, value in flags.items():
        f: str = flag.replace("_", "-")
        f = f"-{f}" if len(f) == 1 else f"--{f}"
        all_flags.append(f)
        if isinstance(value, bool):
            if value is False:
                all_flags.pop()

        elif isinstance(value, list):
            all_flags.extend(value)

        else:
            all_flags.append(value)

    return all_flags


def check_lock_file(project_path: pathlib.Path) -> None:
    """Check if the 'uv.lock' file is consistent with 'pyproject.toml' file.

    Args:
        project_path: The integration path to the project directory
                      that contains 'pyproject.toml' and 'uv.lock' files.

    Raises:
        NonFatalCommandError: If the 'uv lock --check' command indicates that the
                      'uv.lock' file is out of sync or if another error
                      occurs during the check.

    """
    python_version: str = _get_python_version()

    command: list[str] = [
        sys.executable,
        "-m",
        "uv",
        "lock",
        "--check",
        "--project",
        str(project_path),
        "--python",
        python_version,
    ]

    runtime_config: list[str] = _get_runtime_config()
    command.extend(runtime_config)

    try:
        sp.run(  # noqa: S603
            command, cwd=project_path, check=True, text=True, capture_output=True
        )

    except sp.CalledProcessError as e:
        error_output = e.stderr.strip()
        error_output = f"{COMMAND_ERR_MSG.format('uv lock --check')}: {error_output}"
        raise NonFatalCommandError(error_output) from e


def get_files_unmerged_to_main_branch(
    base: str, head_sha: str, integration_path: pathlib.Path
) -> list[pathlib.Path]:
    """Return a list of file names changed in a pull request compared to the main branch.

    Args:
        base: The base branch of the PR.
        head_sha: The head commit SHA of the PR.
        integration_path: The path to the integration directory.

    Returns:
        A list of changed file paths.

    Raises:
        NonFatalCommandError: If the git command fails.

    """
    command: list[str] = [
        "git",
        "diff",
        f"origin/{base}...{head_sha}",
        "--name-only",
        "--diff-filter=ACMRTUXB",
        str(integration_path),
    ]
    try:
        results: sp.CompletedProcess[str] = sp.run(  # noqa: S603
            command, check=True, text=True, capture_output=True
        )
        return [
            p
            for path in results.stdout.strip().splitlines()
            if path and (p := pathlib.Path(path)).exists()
        ]

    except sp.CalledProcessError as error:
        error_output: str = f"{COMMAND_ERR_MSG.format('git diff')}: {error.stderr.strip()}"
        raise NonFatalCommandError(error_output) from error


def get_file_content_from_main_branch(file_path: pathlib.Path) -> str:
    """Return the content of a specific file from the 'main' branch.

    Args:
        file_path: The path to the file.

    Returns:
        The content of the file as a string.

    Raises:
        NonFatalCommandError: If the git command fails (e.g., file not found on main).

    """
    git_path_arg: str = f"origin/main:{file_path.as_posix()}"
    command: list[str] = ["git", "show", git_path_arg]

    try:
        results: sp.CompletedProcess[str] = sp.run(  # noqa: S603
            command, check=True, text=True, capture_output=True
        )

    except sp.CalledProcessError as error:
        error_output: str = (
            f"Failed to get content of '{file_path}' from main branch: {error.stderr.strip()}"
        )
        raise NonFatalCommandError(error_output) from error

    else:
        return results.stdout


def _get_python_version() -> str:
    return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
