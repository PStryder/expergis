"""Local, existing, non-reparse paths for remotely managed file watchers."""
from pathlib import Path


def checked_local_path(value, *, allow_missing_leaf=False):
    if (not isinstance(value, str) or not value or len(value) > 32768
            or value.startswith(("\\\\", "//")) or not Path(value).is_absolute()
            or ".." in Path(value).parts):
        raise PermissionError("An absolute local path without traversal is required")
    path = Path(value)
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            if component == path and allow_missing_leaf:
                continue
            raise
        if component.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Reparse paths are outside monitoring scope")
    return path.resolve(strict=not allow_missing_leaf)
