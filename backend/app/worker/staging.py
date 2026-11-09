"""Secure, ephemeral filesystem workspace staging for static analysis scanners.

Implements Blueprint Section 10.3 (Scanner invocation and workspace staging)
and Threat Mitigations T2 (Subprocess isolation) and T8 (Path safety).
"""

from __future__ import annotations

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


def _on_rmtree_exc(func: Callable[[str], Any], path: str, exc: BaseException) -> None:
    """Error handler for shutil.rmtree to remove read-only attributes on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    try:
        func(path)
    except OSError:
        pass


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
    ) -> None:
        """Initialize an ephemeral staging workspace.

        Args:
            files: Optional iterable of ScannedFile objects to stage immediately.
            base_dir: Base directory for temporary workspaces. Defaults to SCANNER_TEMP_DIR.
            workspace_id: Optional explicit unique identifier. Defaults to random hex UUID.
            source_dirname: Subdirectory name for source files (default 'src').
        """
        if base_dir is not None:
            self.base_dir = Path(base_dir).resolve()
        else:
            settings = get_settings()
            self.base_dir = Path(settings.SCANNER_TEMP_DIR).resolve()

        if workspace_id is not None:
            if not workspace_id.strip():
                raise ValueError("workspace_id cannot be empty or whitespace-only")
            self.workspace_id = workspace_id.strip()
        else:
            self.workspace_id = f"scan-{uuid.uuid4().hex}"

        self.source_dirname = source_dirname.strip()
        if not self.source_dirname or "/" in self.source_dirname or "\\" in self.source_dirname:
            raise ValueError(f"Invalid source_dirname: {source_dirname!r}")

        # Unique workspace path under base_dir
        self.path = (self.base_dir / self.workspace_id).resolve()
        self.source_dir = (self.path / self.source_dirname).resolve()

        # Bidirectional mappings:
        # original normalized path -> staged absolute Path
        self._original_to_staged: dict[str, Path] = {}
        # staged path strings / relative strings -> original normalized path
        self._staged_to_original: dict[str, str] = {}

        self.staged_files: list[ScannedFile] = []
        self.skipped_files: list[ScannedFile] = []
        self._cleaned_up: bool = False
        self._initialized: bool = False

        self._initialize_workspace()

        if files is not None:
            self.stage_files(files)

    def _initialize_workspace(self) -> None:
        """Create the isolated workspace directory structure with restrictive permissions."""
        if self.path.exists():
            raise StagingError(
                f"Workspace directory '{self.path}' already exists; reuse is prohibited"
            )

        # Create base directory if missing
        self.base_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

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

            # 3. Construct destination path inside source_dir
            dest_path = (self.source_dir / normalized_path).resolve()

            # 4. Strict containment check: dest_path must remain strictly inside source_dir
            if not dest_path.is_relative_to(resolved_source_dir):
                raise StagingPathTraversalError(
                    f"File path '{normalized_path}' resolves outside workspace source directory: '{dest_path}'"
                )

            # 5. Symlink check: inspect destination and intermediate parent directories
            self._verify_no_symlinks(dest_path, resolved_source_dir)

            # 6. Create parent directories with restrictive permissions
            dest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

            # 7. Write file content deterministically
            dest_path.write_text(file_item.content, encoding="utf-8")

            # 8. Apply restrictive file permissions where supported (POSIX 0600)
            try:
                dest_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
            except (OSError, NotImplementedError):
                pass

            # 9. Register bidirectional mappings
            self._register_mappings(normalized_path, dest_path)
            self.staged_files.append(file_item)

        logger.debug(
            "Workspace %s staged %d files (%d skipped)",
            self.workspace_id,
            len(self.staged_files),
            len(self.skipped_files),
        )

    def _verify_no_symlinks(self, dest_path: Path, root_dir: Path) -> None:
        """Verify that dest_path and none of its existing parent directories are symlinks."""
        if dest_path.is_symlink():
            raise StagingSymlinkError(f"Destination path '{dest_path}' is a symlink")

        curr: Path | None = dest_path.parent
        while curr is not None and curr != root_dir and curr.is_relative_to(root_dir):
            if curr.exists() and curr.is_symlink():
                raise StagingSymlinkError(
                    f"Intermediate directory '{curr}' in path '{dest_path}' is a symlink"
                )
            curr = curr.parent

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
        if self._cleaned_up or not self.path.exists():
            self._cleaned_up = True
            return

        res_path = self.path.resolve()
        res_base = self.base_dir.resolve()

        # Strict containment safety: path must be strictly inside base_dir
        if res_path == res_base or not res_path.is_relative_to(res_base):
            raise StagingCleanupError(
                f"Refusing to delete directory outside base directory: '{res_path}' (base: '{res_base}')"
            )

        try:
            shutil.rmtree(self.path, onexc=_on_rmtree_exc)
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
