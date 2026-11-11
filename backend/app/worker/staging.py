"""Secure, ephemeral filesystem workspace staging for static analysis scanners.

Implements Blueprint Section 10.3 (Scanner invocation and workspace staging)
and Threat Mitigations T2 (Subprocess isolation) and T8 (Path safety).
"""

from __future__ import annotations

import errno
import logging
import os
import shutil
import stat
import types
import uuid
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, Self

from app.core.config import get_settings
from app.domain.paths import normalize_and_validate_path
from app.worker.scanner import ScannedFile

logger = logging.getLogger("sentinel.worker.staging")


class StagingError(Exception):
    """Base exception for staging workspace operations."""


class StagingPathTraversalError(StagingError):
    """Raised when a file path violates path safety or attempts workspace escape."""


class StagingSymlinkError(StagingError):
    """Raised when a symlink is encountered or would escape the workspace."""


class StagingDuplicatePathError(StagingError):
    """Raised when duplicate normalized paths are submitted in a single batch."""


class StagingCleanupError(StagingError):
    """Raised when workspace cleanup fails on normal exit."""


class StagingPathMappingError(StagingError):
    """Raised when a staged path cannot be translated back to its original path."""


def _is_posix_platform() -> bool:
    """Return True when running on a POSIX host where uid/mode bits apply."""
    return os.name != "nt"


def _on_rmtree_exc(func: Callable[[str], Any], path: str, exc: BaseException) -> None:
    """Error handler for shutil.rmtree to clear read-only attributes without hiding failures."""
    try:
        if not os.path.islink(path):
            os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    func(path)


class StagedWorkspace:
    """Secure, ephemeral filesystem workspace for static analysis scanner engines.

    Guarantees:
    - Creates a unique, non-reusable temporary directory under SCANNER_TEMP_DIR.
    - Stages only ScannedFile items with scanned=True.
    - Preserves safe relative paths and nested directory hierarchy.
    - Rejects path traversal, absolute paths, drive letters, and case-folded duplicates.
    - Enforces symlink escape defenses.
    - Writes file contents safely with restrictive permissions (0700 dir, 0600 file where supported).
    - Maintains bidirectional mappings between original Sentinel paths and staged paths.
    - Translates scanner-reported paths (absolute, relative, forward/backward slashes) back to original.
    - Guarantees recursive cleanup on context exit without modifying anything outside the workspace.
    - Never logs staged source code contents.
    """

    def __init__(
        self,
        files: Iterable[ScannedFile] | None = None,
        *,
        base_dir: str | Path | None = None,
        workspace_id: str | None = None,
        source_dirname: str = "src",
        exclude_filenames: Iterable[str] | None = None,
    ) -> None:
        """Initialize an ephemeral staging workspace.

        Args:
            files: Optional iterable of ScannedFile objects to stage immediately.
            base_dir: Base directory for temporary workspaces. Defaults to SCANNER_TEMP_DIR.
            workspace_id: Optional explicit unique identifier. Defaults to random hex UUID.
            source_dirname: Subdirectory name for source files (default 'src').
            exclude_filenames: Optional collection of case-insensitive basenames to exclude from staging.
        """
        if base_dir is not None:
            raw_base_dir = Path(base_dir)
        else:
            settings = get_settings()
            raw_base_dir = Path(settings.SCANNER_TEMP_DIR)

        self._raw_base_dir = raw_base_dir
        self._validate_base_dir_candidate(self._raw_base_dir)
        self.base_dir = raw_base_dir.resolve()

        if workspace_id is not None:
            cleaned_workspace_id = workspace_id.strip()
            if (
                not cleaned_workspace_id
                or cleaned_workspace_id in {".", ".."}
                or "/" in cleaned_workspace_id
                or "\\" in cleaned_workspace_id
                or "\x00" in cleaned_workspace_id
            ):
                raise ValueError(f"Invalid workspace_id: {workspace_id!r}")
            self.workspace_id = cleaned_workspace_id
        else:
            self.workspace_id = f"scan-{uuid.uuid4().hex}"

        self.source_dirname = source_dirname.strip()
        if (
            not self.source_dirname
            or self.source_dirname in {".", ".."}
            or "/" in self.source_dirname
            or "\\" in self.source_dirname
            or "\x00" in self.source_dirname
        ):
            raise ValueError(f"Invalid source_dirname: {source_dirname!r}")

        self._excluded_filenames: frozenset[str] = frozenset(
            name.strip().casefold()
            for name in (exclude_filenames or ())
            if isinstance(name, str) and name.strip()
        )

        # Unique workspace path strictly contained under base_dir
        self.path = (self.base_dir / self.workspace_id).resolve()
        if self.path == self.base_dir or not self.path.is_relative_to(self.base_dir):
            raise StagingPathTraversalError(
                f"Workspace path '{self.path}' escapes base directory '{self.base_dir}'"
            )
        self.source_dir = (self.path / self.source_dirname).resolve()
        if self.source_dir == self.path or not self.source_dir.is_relative_to(self.path):
            raise StagingPathTraversalError(
                f"Source directory '{self.source_dir}' escapes workspace '{self.path}'"
            )

        # Bidirectional mappings:
        # original normalized path -> staged absolute Path
        self._original_to_staged: dict[str, Path] = {}
        # staged path strings / relative strings -> original normalized path
        self._staged_to_original: dict[str, str] = {}

        self.staged_files: list[ScannedFile] = []
        self.skipped_files: list[ScannedFile] = []
        self.excluded_files: list[ScannedFile] = []
        self._cleaned_up: bool = False
        self._initialized: bool = False

        self._initialize_workspace()

        if files is not None:
            self.stage_files(files)

    def _validate_base_dir_candidate(self, base_dir: Path) -> None:
        """Validate pre-existing base_dir is not a symlink and has safe POSIX ownership/mode."""
        if not os.path.lexists(base_dir):
            return

        try:
            st = os.lstat(base_dir)
        except OSError as exc:
            raise StagingError(
                f"Unable to inspect base workspace directory '{base_dir}': {exc}"
            ) from exc

        if stat.S_ISLNK(st.st_mode):
            raise StagingSymlinkError(
                f"Base workspace directory '{base_dir}' must not be a symlink"
            )
        if not stat.S_ISDIR(st.st_mode):
            raise StagingError(f"Base workspace path '{base_dir}' is not a directory")

        if _is_posix_platform():
            geteuid = getattr(os, "geteuid", None)
            if callable(geteuid) and st.st_uid != geteuid():
                raise StagingError(
                    f"Base workspace directory '{base_dir}' is not owned by the current user"
                )
            if st.st_mode & stat.S_IWOTH:
                raise StagingError(
                    f"Base workspace directory '{base_dir}' has unsafe world-writable permissions"
                )

    def _initialize_workspace(self) -> None:
        """Create the isolated workspace directory structure with restrictive permissions."""
        if os.path.lexists(self.path):
            raise StagingError(
                f"Workspace directory '{self.path}' already exists; reuse is prohibited"
            )

        self._validate_base_dir_candidate(self._raw_base_dir)

        # Create base directory if missing
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._validate_base_dir_candidate(self.base_dir)

        if os.path.lexists(self.path):
            raise StagingError(
                f"Workspace directory '{self.path}' already exists; reuse is prohibited"
            )

        # Create unique workspace root and source directory
        self.path.mkdir(parents=False, exist_ok=False, mode=0o700)
        self.source_dir.mkdir(parents=False, exist_ok=False, mode=0o700)
        self._initialized = True

        logger.debug("Initialized staged workspace at %s", self.path)

    def stage_files(self, files: Iterable[ScannedFile]) -> None:
        """Stage an iterable of ScannedFile objects into the source directory.

        Args:
            files: Sequence or iterable of ScannedFile items.

        Raises:
            StagingPathTraversalError: If any path violates traversal rules or escapes the source directory.
            StagingSymlinkError: If any path attempts to traverse or create a symlink.
            StagingDuplicatePathError: If duplicate paths are provided after case-folding.
        """
        seen_casefold_paths: set[str] = {f.path.casefold() for f in self.staged_files}

        resolved_source_dir = self.source_dir.resolve()

        for file_item in files:
            if not isinstance(file_item, ScannedFile):
                raise TypeError(f"Expected ScannedFile object, got '{type(file_item).__name__}'")

            # Skip unscanned files (Workflow A & §10.1)
            if not file_item.scanned:
                self.skipped_files.append(file_item)
                logger.debug(
                    "Skipping unscanned file '%s' (reason: %s)",
                    file_item.path,
                    file_item.skip_reason,
                )
                continue

            # 1. Normalize and validate relative path using Sentinel domain rules
            try:
                normalized_path = normalize_and_validate_path(file_item.path)
            except (ValueError, TypeError) as exc:
                raise StagingPathTraversalError(
                    f"Invalid or unsafe file path '{file_item.path}': {exc}"
                ) from exc

            # 2. Case-folded path uniqueness
            casefolded = normalized_path.casefold()
            if casefolded in seen_casefold_paths:
                raise StagingDuplicatePathError(
                    f"Duplicate file path '{normalized_path}' after case-folding normalization"
                )
            seen_casefold_paths.add(casefolded)

            # Exclude scanner-control files by basename without mutating input payloads
            if Path(normalized_path).name.casefold() in self._excluded_filenames:
                self.excluded_files.append(file_item)
                logger.debug("Excluding scanner-control file '%s' from staging", normalized_path)
                continue

            # 3. Validate unresolved destination and existing ancestors for symlinks BEFORE .resolve()
            unresolved_dest = self.source_dir / normalized_path
            self._verify_no_symlinks(unresolved_dest, self.source_dir)

            # 4. Strict containment check: dest_path must remain strictly inside source_dir
            dest_path = unresolved_dest.resolve()
            if not dest_path.is_relative_to(resolved_source_dir):
                raise StagingPathTraversalError(
                    f"File path '{normalized_path}' resolves outside workspace source directory: '{dest_path}'"
                )

            # 5. Re-verify no symlinks exist on resolved path/ancestors
            self._verify_no_symlinks(dest_path, resolved_source_dir)

            # 6. Create parent directories component-by-component without traversing symlinks
            curr_dir = self.source_dir
            for part in Path(normalized_path).parent.parts:
                curr_dir = curr_dir / part
                if os.path.lexists(curr_dir):
                    dir_stat = os.lstat(curr_dir)
                    if stat.S_ISLNK(dir_stat.st_mode):
                        raise StagingSymlinkError(
                            f"Intermediate directory '{curr_dir}' in path '{unresolved_dest}' is a symlink"
                        )
                    if not stat.S_ISDIR(dir_stat.st_mode):
                        raise StagingError(f"Intermediate path '{curr_dir}' is not a directory")
                else:
                    try:
                        curr_dir.mkdir(parents=False, exist_ok=False, mode=0o700)
                    except FileExistsError:
                        dir_stat = os.lstat(curr_dir)
                        if stat.S_ISLNK(dir_stat.st_mode):
                            raise StagingSymlinkError(
                                f"Intermediate directory '{curr_dir}' in path '{unresolved_dest}' is a symlink"
                            ) from None
                        if not stat.S_ISDIR(dir_stat.st_mode):
                            raise StagingError(
                                f"Intermediate path '{curr_dir}' is not a directory"
                            ) from None

            # 7. Create regular file via descriptor with O_NOFOLLOW + 0600 permissions
            o_nofollow = getattr(os, "O_NOFOLLOW", 0)
            open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow
            try:
                fd = os.open(unresolved_dest, open_flags, stat.S_IRUSR | stat.S_IWUSR)
            except OSError as exc:
                if exc.errno in {
                    getattr(errno, "ELOOP", -1),
                    getattr(errno, "EMLINK", -1),
                } or (
                    os.path.lexists(unresolved_dest)
                    and stat.S_ISLNK(os.lstat(unresolved_dest).st_mode)
                ):
                    raise StagingSymlinkError(
                        f"Destination path '{unresolved_dest}' is a symlink"
                    ) from exc
                raise StagingError(
                    f"Unable to stage file '{normalized_path}' safely: {exc}"
                ) from exc

            try:
                fd_stat = os.fstat(fd)
                if not stat.S_ISREG(fd_stat.st_mode):
                    raise StagingError(
                        f"Staged destination '{unresolved_dest}' is not a regular file"
                    )
                if hasattr(os, "fchmod"):
                    try:
                        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
                    except (OSError, NotImplementedError):
                        pass
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                    fd = -1
                    handle.write(file_item.content)
            finally:
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

            # 8. Ensure restrictive file permissions on platforms without fchmod
            if not hasattr(os, "fchmod"):
                try:
                    dest_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
                except (OSError, NotImplementedError):
                    pass

            # 9. Register bidirectional mappings
            self._register_mappings(normalized_path, dest_path)
            self.staged_files.append(file_item)

        logger.debug(
            "Workspace %s staged %d files (%d skipped, %d excluded)",
            self.workspace_id,
            len(self.staged_files),
            len(self.skipped_files),
            len(self.excluded_files),
        )

    def _verify_no_symlinks(self, dest_path: Path, root_dir: Path) -> None:
        """Verify dest_path and all existing components up to root_dir are not symlinks."""
        if os.path.lexists(root_dir):
            root_stat = os.lstat(root_dir)
            if stat.S_ISLNK(root_stat.st_mode):
                raise StagingSymlinkError(f"Workspace root '{root_dir}' is a symlink")
            if not stat.S_ISDIR(root_stat.st_mode):
                raise StagingError(f"Workspace root '{root_dir}' is not a directory")

        curr: Path = dest_path
        while True:
            if os.path.lexists(curr):
                st = os.lstat(curr)
                if stat.S_ISLNK(st.st_mode):
                    if curr == dest_path:
                        raise StagingSymlinkError(f"Destination path '{dest_path}' is a symlink")
                    raise StagingSymlinkError(
                        f"Intermediate directory '{curr}' in path '{dest_path}' is a symlink"
                    )
                if curr != dest_path and not stat.S_ISDIR(st.st_mode):
                    raise StagingError(f"Intermediate path '{curr}' is not a directory")

            if curr == root_dir:
                break

            parent = curr.parent
            if parent == curr or not parent.is_relative_to(root_dir):
                raise StagingPathTraversalError(
                    f"Path '{dest_path}' escapes workspace source directory '{root_dir}'"
                )
            curr = parent

    def _register_mappings(self, original_norm_path: str, staged_path: Path) -> None:
        """Register lookup keys for bidirectional path resolution."""
        self._original_to_staged[original_norm_path] = staged_path

        resolved_staged = staged_path.resolve()
        posix_abs = resolved_staged.as_posix()
        str_abs = str(resolved_staged)

        # Lookup by absolute resolved path
        self._staged_to_original[posix_abs] = original_norm_path
        self._staged_to_original[str_abs] = original_norm_path

        # Lookup by path relative to source_dir
        self._staged_to_original[original_norm_path] = original_norm_path

        # Lookup by path relative to workspace root (e.g. 'src/app/main.py')
        rel_from_root = f"{self.source_dirname}/{original_norm_path}"
        self._staged_to_original[rel_from_root] = original_norm_path

    def get_staged_path(self, original_path: str) -> Path:
        """Translate an original Sentinel path to its staged Path on disk.

        Args:
            original_path: The relative path originally provided in the scan payload.

        Returns:
            Absolute Path to the staged file.

        Raises:
            StagingPathMappingError: If original_path was not staged in this workspace.
        """
        try:
            norm = normalize_and_validate_path(original_path)
        except Exception as exc:
            raise StagingPathMappingError(
                f"Path '{original_path}' is not a valid relative path: {exc}"
            ) from exc

        if norm in self._original_to_staged:
            return self._original_to_staged[norm]

        raise StagingPathMappingError(
            f"Original path '{original_path}' was not staged in workspace '{self.workspace_id}'"
        )

    def get_original_path(self, staged_path: str | Path) -> str:
        """Translate a scanner-reported file path back to its original Sentinel path.

        Handles:
        - Absolute paths (POSIX `/tmp/.../src/app/auth.py` or Windows `D:\\tmp\\...\\src\\app\\auth.py`)
        - Relative paths from workspace root (`src/app/auth.py` or `src\\app\\auth.py`)
        - Relative paths from source directory (`app/auth.py` or `app\\auth.py`)
        - Leading `./` segments.

        Args:
            staged_path: The file path string or Path object reported by the scanner.

        Returns:
            The normalized relative Sentinel file path.

        Raises:
            StagingPathMappingError: If the staged path cannot be mapped to any staged file.
        """
        if not staged_path:
            raise StagingPathMappingError("staged_path cannot be empty")

        p_str = str(staged_path).strip().replace("\\", "/")

        # 1. Direct dictionary match
        if p_str in self._staged_to_original:
            return self._staged_to_original[p_str]

        # 2. Check if p_str is an absolute path or exists under workspace
        try:
            p_obj = Path(staged_path).resolve()
            source_dir_res = self.source_dir.resolve()
            if p_obj.is_relative_to(source_dir_res):
                rel_from_src = p_obj.relative_to(source_dir_res).as_posix()
                if rel_from_src in self._original_to_staged:
                    return rel_from_src
        except (ValueError, OSError):
            pass

        # 3. Handle relative prefixes
        cleaned = p_str
        while cleaned.startswith("./"):
            cleaned = cleaned[2:]

        if cleaned in self._staged_to_original:
            return self._staged_to_original[cleaned]

        if cleaned.startswith(f"{self.source_dirname}/"):
            sub_path = cleaned[len(self.source_dirname) + 1 :]
            if sub_path in self._original_to_staged:
                return sub_path

        raise StagingPathMappingError(
            f"Staged path '{staged_path}' cannot be mapped to any file staged in workspace '{self.workspace_id}'"
        )

    def cleanup(self) -> None:
        """Recursively delete the workspace directory and all contained files.

        Guarantees:
        - Never deletes the base temporary directory.
        - Never deletes directories outside the base temporary directory.
        - Handles read-only file attributes portably on Windows.

        Raises:
            StagingCleanupError: If cleanup fails or safety invariants are violated.
        """
        if self._cleaned_up or not os.path.lexists(self.path):
            self._cleaned_up = True
            return

        if os.path.islink(self.path):
            raise StagingCleanupError(f"Refusing to delete symlink workspace path: '{self.path}'")

        res_path = self.path.resolve()
        res_base = self.base_dir.resolve()

        # Strict containment safety: path must be strictly inside base_dir
        if res_path == res_base or not res_path.is_relative_to(res_base):
            raise StagingCleanupError(
                f"Refusing to delete directory outside base directory: '{res_path}' (base: '{res_base}')"
            )

        try:
            shutil.rmtree(self.path, onexc=_on_rmtree_exc)
            if os.path.lexists(self.path):
                raise OSError("Staged workspace path still exists after recursive removal")
            self._cleaned_up = True
            logger.debug("Successfully cleaned up staged workspace at %s", self.path)
        except Exception as exc:
            raise StagingCleanupError(
                f"Failed to clean up staged workspace at '{self.path}': {exc}"
            ) from exc

    def __enter__(self) -> Self:
        """Enter the staged workspace context."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: types.TracebackType | None,
    ) -> None:
        """Exit the staged workspace context, guaranteeing recursive cleanup.

        If an exception occurred inside the context block, cleanup failures are logged
        without suppressing the original exception. If no exception occurred, cleanup
        failures raise StagingCleanupError.
        """
        try:
            self.cleanup()
        except Exception as cleanup_err:
            logger.warning(
                "Staged workspace cleanup failed for %s: %s",
                self.path,
                cleanup_err,
            )
            if exc_val is None:
                raise StagingCleanupError(
                    f"Failed to clean up workspace '{self.path}': {cleanup_err}"
                ) from cleanup_err
