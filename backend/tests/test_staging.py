"""Unit tests for secure ephemeral staging workspace (Milestone 1 / Part A).

Validates:
- Workspace creation and uniqueness.
- Correct staging of scanned files.
- Skipping unscanned files.
- Nested paths and bidirectional mapping.
- Rejection of traversal and absolute paths.
- Duplicate normalized path rejection.
- Symlink/path containment protection.
- Cleanup after normal execution.
- Cleanup after an exception.
- No deletion outside the temporary workspace.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest

from app.worker.scanner import ScannedFile
from app.worker.staging import (
    StagedWorkspace,
    StagingCleanupError,
    StagingDuplicatePathError,
    StagingError,
    StagingPathMappingError,
    StagingPathTraversalError,
    StagingSymlinkError,
)


@pytest.fixture
def temp_base_dir() -> Generator[Path, None, None]:
    """Provide a temporary directory to act as base_dir for staging workspaces."""
    with tempfile.TemporaryDirectory(prefix="sentinel-test-base-") as tmp:
        yield Path(tmp).resolve()


class TestStagedWorkspaceLifecycle:
    """Tests for workspace creation, directory uniqueness, and recursive cleanup."""

    def test_workspace_creation_and_uniqueness(self, temp_base_dir: Path) -> None:
        """Workspaces created under the same base directory receive distinct paths and exist."""
        with (
            StagedWorkspace(base_dir=temp_base_dir) as ws1,
            StagedWorkspace(base_dir=temp_base_dir) as ws2,
        ):
            assert ws1.path != ws2.path
            assert ws1.path.is_dir()
            assert ws2.path.is_dir()
            assert ws1.source_dir.is_dir()
            assert ws2.source_dir.is_dir()
            assert ws1.path.parent == temp_base_dir
            assert ws2.path.parent == temp_base_dir

    def test_never_reuses_existing_workspace(self, temp_base_dir: Path) -> None:
        """Attempting to initialize a workspace with an existing workspace_id raises StagingError."""
        custom_id = "test-fixed-workspace"
        with StagedWorkspace(base_dir=temp_base_dir, workspace_id=custom_id) as ws1:
            assert ws1.path.is_dir()
            with pytest.raises(StagingError, match="already exists"):
                StagedWorkspace(base_dir=temp_base_dir, workspace_id=custom_id)

    def test_cleanup_after_normal_execution(self, temp_base_dir: Path) -> None:
        """Workspace directory and contents are deleted completely upon clean context exit."""
        ws_path: Path
        with StagedWorkspace(
            files=[ScannedFile(path="app/main.py", content="x = 1\n", scanned=True)],
            base_dir=temp_base_dir,
        ) as ws:
            ws_path = ws.path
            assert ws_path.is_dir()
            assert (ws.source_dir / "app/main.py").is_file()

        assert not ws_path.exists()

    def test_cleanup_after_exception(self, temp_base_dir: Path) -> None:
        """Workspace is cleaned up when an exception occurs inside the context, without swallowing it."""
        ws_path: Path
        with (
            pytest.raises(RuntimeError, match="deliberate failure"),
            StagedWorkspace(
                files=[ScannedFile(path="app/test.py", content="pass\n", scanned=True)],
                base_dir=temp_base_dir,
            ) as ws,
        ):
            ws_path = ws.path
            assert ws_path.is_dir()
            raise RuntimeError("deliberate failure")

        assert not ws_path.exists()

    def test_no_deletion_outside_workspace(self, temp_base_dir: Path) -> None:
        """Canary files in the base directory remain intact after workspace cleanup."""
        canary_file = temp_base_dir / "external_canary.txt"
        canary_file.write_text("critical external asset", encoding="utf-8")

        with StagedWorkspace(
            files=[ScannedFile(path="internal.py", content="print(1)", scanned=True)],
            base_dir=temp_base_dir,
        ) as ws:
            assert ws.path.is_dir()

        # Workspace is removed, but canary in base directory persists untouched
        assert not ws.path.exists()
        assert canary_file.is_file()
        assert canary_file.read_text(encoding="utf-8") == "critical external asset"

    def test_cleanup_safety_refuses_base_dir_deletion(self, temp_base_dir: Path) -> None:
        """Workspace refuse to delete base_dir or directories outside base_dir."""
        ws = StagedWorkspace(base_dir=temp_base_dir)
        # Artificially point path to base_dir
        ws.path = temp_base_dir
        with pytest.raises(StagingCleanupError, match="Refusing to delete directory outside base"):
            ws.cleanup()


class TestStagedFilesManagement:
    """Tests for file staging, filtering, and content persistence."""

    def test_correct_staging_of_scanned_files(self, temp_base_dir: Path) -> None:
        """Only scanned files are written with exact content and preserved directory structure."""
        files = [
            ScannedFile(path="src/index.js", content="console.log('hello');\n", scanned=True),
            ScannedFile(path="config/settings.json", content='{"debug": true}\n', scanned=True),
        ]
        with StagedWorkspace(files=files, base_dir=temp_base_dir) as ws:
            assert len(ws.staged_files) == 2
            assert len(ws.skipped_files) == 0

            file1 = ws.source_dir / "src/index.js"
            file2 = ws.source_dir / "config/settings.json"

            assert file1.is_file()
            assert file2.is_file()
            assert file1.read_text(encoding="utf-8") == "console.log('hello');\n"
            assert file2.read_text(encoding="utf-8") == '{"debug": true}\n'

    def test_skipping_unscanned_files(self, temp_base_dir: Path) -> None:
        """Files with scanned=False are tracked in skipped_files and not written to disk."""
        files = [
            ScannedFile(path="valid.py", content="print('ok')\n", scanned=True),
            ScannedFile(
                path="binary.png",
                content="<bytes>",
                scanned=False,
                skip_reason="unsupported_extension",
            ),
            ScannedFile(
                path="bundle.min.js",
                content="var a=1;",
                scanned=False,
                skip_reason="minified_or_generated",
            ),
        ]
        with StagedWorkspace(files=files, base_dir=temp_base_dir) as ws:
            assert len(ws.staged_files) == 1
            assert len(ws.skipped_files) == 2
            assert ws.skipped_files[0].path == "binary.png"
            assert ws.skipped_files[1].path == "bundle.min.js"

            assert (ws.source_dir / "valid.py").is_file()
            assert not (ws.source_dir / "binary.png").exists()
            assert not (ws.source_dir / "bundle.min.js").exists()


class TestBidirectionalPathMapping:
    """Tests for resolving between Sentinel relative paths and staged disk paths."""

    def test_nested_paths_and_bidirectional_mapping(self, temp_base_dir: Path) -> None:
        """StagedWorkspace maps original paths to absolute paths and reverse-resolves multiple formats."""
        files = [
            ScannedFile(path="deep/nested/pkg/module.py", content="def f(): pass\n", scanned=True),
        ]
        with StagedWorkspace(files=files, base_dir=temp_base_dir) as ws:
            orig = "deep/nested/pkg/module.py"
            staged = ws.get_staged_path(orig)

            assert staged.is_file()
            assert staged == ws.source_dir / "deep/nested/pkg/module.py"

            # Reverse mappings
            # 1. Exact absolute Path
            assert ws.get_original_path(staged) == orig
            # 2. String absolute path
            assert ws.get_original_path(str(staged)) == orig
            # 3. Path with Windows backslashes
            assert ws.get_original_path(str(staged).replace("/", "\\")) == orig
            # 4. Relative to workspace root ('src/deep/nested/pkg/module.py')
            assert ws.get_original_path(f"src/{orig}") == orig
            # 5. Relative with backslashes ('src\\deep\\nested\\pkg\\module.py')
            assert ws.get_original_path(f"src\\{orig.replace('/', '\\')}") == orig
            # 6. Relative to source_dir ('deep/nested/pkg/module.py')
            assert ws.get_original_path(orig) == orig
            # 7. Leading './' prefix
            assert ws.get_original_path(f"./src/{orig}") == orig

    def test_mapping_unknown_path_raises_error(self, temp_base_dir: Path) -> None:
        """Translating unmapped paths raises StagingPathMappingError."""
        with StagedWorkspace(
            files=[ScannedFile(path="app.py", content="pass", scanned=True)],
            base_dir=temp_base_dir,
        ) as ws:
            with pytest.raises(StagingPathMappingError, match="was not staged"):
                ws.get_staged_path("nonexistent.py")

            with pytest.raises(StagingPathMappingError, match="cannot be mapped"):
                ws.get_original_path("other/file.py")

            with pytest.raises(StagingPathMappingError, match="cannot be empty"):
                ws.get_original_path("")


class TestStagingSecurityControls:
    """Tests verifying path traversal, symlink defenses, and duplicate rejection."""

    @pytest.mark.parametrize(
        "unsafe_path",
        [
            "../escape.py",
            "foo/../../bar.py",
            "/etc/passwd",
            "/app/main.py",
            "C:/Windows/System32/calc.exe",
            "d:/sentinel/app.py",
            "foo\\bar.py",
            "app/foo|bar.py",
            "app/trailing/slash/",
            "app/space.py ",
            "app/dot.py.",
        ],
    )
    def test_rejection_of_traversal_and_absolute_paths(
        self, temp_base_dir: Path, unsafe_path: str
    ) -> None:
        """Unsafe paths violating Sentinel normalization are strictly rejected with StagingPathTraversalError."""
        with (
            StagedWorkspace(base_dir=temp_base_dir) as ws,
            pytest.raises(StagingPathTraversalError),
        ):
            ws.stage_files([ScannedFile(path=unsafe_path, content="test", scanned=True)])

    def test_duplicate_normalized_path_rejection(self, temp_base_dir: Path) -> None:
        """Files that resolve to identical case-folded paths in the same batch are rejected."""
        files = [
            ScannedFile(path="services/auth.py", content="v1", scanned=True),
            ScannedFile(path="SERVICES/AUTH.PY", content="v2", scanned=True),
        ]
        with (
            StagedWorkspace(base_dir=temp_base_dir) as ws,
            pytest.raises(StagingDuplicatePathError, match="Duplicate file path"),
        ):
            ws.stage_files(files)

    def test_symlink_protection(self, temp_base_dir: Path) -> None:
        """Attempts to stage files into existing symlink directories or files are rejected."""
        with StagedWorkspace(base_dir=temp_base_dir) as ws:
            # Create a target directory outside and a symlink inside source_dir
            external_target = temp_base_dir / "external_target"
            external_target.mkdir()

            symlink_dir = ws.source_dir / "symlink_dir"
            try:
                os.symlink(external_target, symlink_dir, target_is_directory=True)
            except (OSError, NotImplementedError):
                pytest.skip("Symlink creation not supported in this test environment")

            # Staging a file into the symlink directory must raise StagingSymlinkError
            with pytest.raises(StagingSymlinkError, match="is a symlink"):
                ws.stage_files(
                    [ScannedFile(path="symlink_dir/pwned.py", content="evil", scanned=True)]
                )
