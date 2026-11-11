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
from typing import Any

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


class TestStagedWorkspaceCleanupHardening:
    """Regression tests ensuring StagedWorkspace never hides cleanup failures or follows symlinks."""

    def test_cleanup_raises_when_entries_remain_after_rmtree(
        self, temp_base_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """cleanup() must raise StagingCleanupError if files cannot be removed."""
        from app.worker.staging import _on_rmtree_exc

        ws = StagedWorkspace(
            files=[ScannedFile(path="app.py", content="SECRET='abc'\n", scanned=True)],
            base_dir=temp_base_dir,
        )
        ws_path = ws.path
        assert ws_path.is_dir()

        # Verify _on_rmtree_exc no longer swallows unrecoverable OSError
        def always_fail(_path: str) -> None:
            raise PermissionError("locked file")

        with pytest.raises(PermissionError, match="locked file"):
            _on_rmtree_exc(always_fail, str(ws.source_dir / "app.py"), PermissionError("locked"))

        # Verify cleanup() detects leftover directory even if shutil.rmtree silently returned
        monkeypatch.setattr("app.worker.staging.shutil.rmtree", lambda *a, **kw: None)
        with pytest.raises(StagingCleanupError, match="still exists"):
            ws.cleanup()
        assert ws._cleaned_up is False
        monkeypatch.undo()

        # Real cleanup still removes everything once unblocked
        ws.cleanup()
        assert not ws_path.exists()
        assert ws._cleaned_up is True

    def test_on_rmtree_exc_never_chmod_symlink_targets(
        self, temp_base_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Cleanup error handler must never call os.chmod on symlinks to protect external files."""
        import os

        from app.worker.staging import _on_rmtree_exc

        external_file = temp_base_dir / "external.txt"
        external_file.write_text("do not chmod", encoding="utf-8")

        link_path = temp_base_dir / "sym_inside"
        try:
            os.symlink(external_file, link_path)
        except OSError:
            # Verify via Path.is_symlink / os.path.islink mock if OS lacks symlink privilege
            monkeypatch.setattr(os.path, "islink", lambda p: str(p) == str(link_path))

        chmod_calls: list[str] = []
        monkeypatch.setattr(os, "chmod", lambda p, m: chmod_calls.append(str(p)))

        _on_rmtree_exc(lambda _p: None, str(link_path), PermissionError("perm"))
        assert chmod_calls == []


class TestStagingSymlinkAndControlHardening:
    """Regression tests for symlink resolution order, dangling links, POSIX base_dir, and exclusions."""

    def test_internal_external_and_dangling_symlinks_rejected_with_normal_nesting_preserved(
        self, temp_base_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Internal, external, and dangling symlinks raise StagingSymlinkError while normal files stage."""
        import stat as stat_mod

        external_dir = temp_base_dir / "external_dir"
        external_dir.mkdir()
        external_file = temp_base_dir / "external_secret.txt"
        external_file.write_text("outside", encoding="utf-8")

        # 1. Normal nested file stages safely with regular non-symlink permissions
        with StagedWorkspace(base_dir=temp_base_dir) as ws_ok:
            ws_ok.stage_files(
                [ScannedFile(path="pkg/sub/module.py", content="VALUE = 1\n", scanned=True)]
            )
            staged = ws_ok.get_staged_path("pkg/sub/module.py")
            assert staged.is_file()
            assert not os.path.islink(staged)
            assert staged.read_text(encoding="utf-8") == "VALUE = 1\n"

        # 2. Internal symlink inside source_dir -> real_dir inside source_dir must STILL be rejected
        with StagedWorkspace(base_dir=temp_base_dir) as ws_int:
            real_sub = ws_int.source_dir / "real_sub"
            real_sub.mkdir()
            internal_link = ws_int.source_dir / "internal_link"
            try:
                os.symlink(real_sub, internal_link, target_is_directory=True)
            except (OSError, NotImplementedError):
                real_lstat = os.lstat

                def fake_internal_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
                    res = real_lstat(p, *args, **kwargs)
                    if Path(p) == internal_link:
                        fake = list(res)
                        fake[0] = (fake[0] & ~0o170000) | stat_mod.S_IFLNK
                        return os.stat_result(fake)
                    return res

                real_sub.mkdir(exist_ok=True)
                internal_link.mkdir()
                monkeypatch.setattr(
                    os.path,
                    "lexists",
                    lambda p: True if Path(p) == internal_link else Path(p).exists(),
                )
                monkeypatch.setattr(os, "lstat", fake_internal_lstat)

            with pytest.raises(StagingSymlinkError, match="is a symlink"):
                ws_int.stage_files(
                    [ScannedFile(path="internal_link/escape.py", content="x = 1", scanned=True)]
                )
            assert not (real_sub / "escape.py").exists()
            monkeypatch.undo()

        # 3. Dangling symlink directory and dangling symlink destination are both caught via lexists/lstat
        with StagedWorkspace(base_dir=temp_base_dir) as ws_dangle:
            dangling_dir = ws_dangle.source_dir / "dangling_dir"
            dangling_file = ws_dangle.source_dir / "dangling_leaf.py"
            missing_target = temp_base_dir / "does_not_exist_target"
            try:
                os.symlink(missing_target, dangling_dir, target_is_directory=True)
                os.symlink(missing_target, dangling_file, target_is_directory=False)
            except (OSError, NotImplementedError):
                real_lstat = os.lstat
                real_lexists = os.path.lexists

                def fake_dangle_lexists(p: Any) -> bool:
                    if Path(p) in {dangling_dir, dangling_file}:
                        return True
                    return bool(real_lexists(p))

                def fake_dangle_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
                    if Path(p) in {dangling_dir, dangling_file}:
                        sample = list(real_lstat(ws_dangle.source_dir))
                        sample[0] = (sample[0] & ~0o170000) | stat_mod.S_IFLNK
                        return os.stat_result(sample)
                    return real_lstat(p, *args, **kwargs)

                monkeypatch.setattr(os.path, "lexists", fake_dangle_lexists)
                monkeypatch.setattr(os, "lstat", fake_dangle_lstat)

            with pytest.raises(StagingSymlinkError, match="is a symlink"):
                ws_dangle.stage_files(
                    [ScannedFile(path="dangling_dir/payload.py", content="x", scanned=True)]
                )
            with pytest.raises(StagingSymlinkError, match="is a symlink"):
                ws_dangle.stage_files(
                    [ScannedFile(path="dangling_leaf.py", content="x", scanned=True)]
                )
            assert not missing_target.exists()
            monkeypatch.undo()

    def test_dangling_workspace_root_and_posix_base_dir_validation(
        self, temp_base_dir: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Dangling workspace root symlink is detected by init/cleanup and unsafe base_dir is rejected."""
        import stat as stat_mod

        dangling_ws_id = "scan-dangling-root"
        dangling_ws_path = temp_base_dir / dangling_ws_id
        missing = temp_base_dir / "missing_root_target"

        real_lexists = os.path.lexists
        real_islink = os.path.islink
        monkeypatch.setattr(
            os.path, "lexists", lambda p: True if Path(p) == dangling_ws_path else real_lexists(p)
        )
        with pytest.raises(StagingError, match="already exists"):
            StagedWorkspace(base_dir=temp_base_dir, workspace_id=dangling_ws_id)
        monkeypatch.undo()

        # Symlink workspace root refused by cleanup even when pointing nowhere
        ws_cleanup = StagedWorkspace(base_dir=temp_base_dir)
        monkeypatch.setattr(
            os.path, "lexists", lambda p: True if Path(p) == ws_cleanup.path else real_lexists(p)
        )
        monkeypatch.setattr(
            os.path, "islink", lambda p: True if Path(p) == ws_cleanup.path else real_islink(p)
        )
        with pytest.raises(StagingCleanupError, match="symlink"):
            ws_cleanup.cleanup()
        monkeypatch.undo()
        ws_cleanup.cleanup()
        assert not missing.exists()

        # Pre-existing POSIX base_dir wrong ownership or world-writable mode rejected
        unsafe_base = temp_base_dir / "unsafe_posix_base"
        unsafe_base.mkdir()
        real_lstat = os.lstat

        def fake_ww_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
            st = list(real_lstat(p, *args, **kwargs))
            if Path(p) == unsafe_base:
                st[0] = (st[0] & ~0o777) | stat_mod.S_IFDIR | 0o777
                st[4] = 1000
            return os.stat_result(st)

        monkeypatch.setattr("app.worker.staging._is_posix_platform", lambda: True)
        monkeypatch.setattr("app.worker.staging.os.geteuid", lambda: 1000, raising=False)
        monkeypatch.setattr(os, "lstat", fake_ww_lstat)
        with pytest.raises(StagingError, match="world-writable"):
            StagedWorkspace(base_dir=unsafe_base)

        def fake_uid_lstat(p: Any, *args: Any, **kwargs: Any) -> Any:
            st = list(real_lstat(p, *args, **kwargs))
            if Path(p) == unsafe_base:
                st[0] = (st[0] & ~0o777) | stat_mod.S_IFDIR | 0o700
                st[4] = 9999
            return os.stat_result(st)

        monkeypatch.setattr(os, "lstat", fake_uid_lstat)
        with pytest.raises(StagingError, match="not owned by the current user"):
            StagedWorkspace(base_dir=unsafe_base)
        monkeypatch.undo()

        # Real POSIX 0777 base_dir test where OS enforces modes
        if os.name != "nt":
            posix_base = temp_base_dir / "real_ww_base"
            posix_base.mkdir()
            posix_base.chmod(0o777)
            try:
                with pytest.raises(StagingError, match="world-writable"):
                    StagedWorkspace(base_dir=posix_base)
            finally:
                posix_base.chmod(0o700)

    def test_exclude_filenames_skips_control_files_without_mutating_inputs(
        self, temp_base_dir: Path
    ) -> None:
        """Excluded filenames never hit disk while normal scanned files stage and inputs stay untouched."""
        cfg = ScannedFile(path=".gitleaks.toml", content="[extend]\n", scanned=True)
        nested_ign = ScannedFile(path="sub/.GitleaksIgnore", content="rule1\n", scanned=True)
        code = ScannedFile(path="sub/app.py", content="x = 1\n", scanned=True)
        files = [cfg, nested_ign, code]

        with StagedWorkspace(
            files,
            base_dir=temp_base_dir,
            exclude_filenames={".gitleaks.toml", ".gitleaksignore"},
        ) as ws:
            assert len(ws.staged_files) == 1
            assert ws.staged_files[0].path == "sub/app.py"
            assert len(ws.excluded_files) == 2
            assert ws.skipped_files == []
            assert (ws.source_dir / "sub/app.py").is_file()
            assert not (ws.source_dir / ".gitleaks.toml").exists()
            assert not (ws.source_dir / "sub/.GitleaksIgnore").exists()
            assert cfg.scanned is True
            assert nested_ign.scanned is True

    def test_traversal_workspace_id_and_source_dirname_rejected(self, temp_base_dir: Path) -> None:
        """Traversal segments, slashes, and NUL bytes in workspace_id or source_dirname fail fast."""
        escaped_target = temp_base_dir.parent / "escaped_ws_dir"
        for bad_ws_id in ("", "   ", ".", "..", "../escaped_ws_dir", "a/b", "a\\b", "bad\x00ws"):
            with pytest.raises(ValueError):
                StagedWorkspace(base_dir=temp_base_dir, workspace_id=bad_ws_id)
        assert not escaped_target.exists()

        for bad_src in ("", "   ", ".", "..", "src/sub", "src\\sub", "bad\x00src"):
            with pytest.raises(ValueError):
                StagedWorkspace(base_dir=temp_base_dir, source_dirname=bad_src)
