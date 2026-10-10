"""Security regression tests for file upload validation and access control."""

import asyncio
import io
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException, UploadFile

from decemsg.api import messages as api
from decemsg.core.config import AppConfig, MessagingConfig
from decemsg.models.uploaded_file import UploadedFile


@pytest.mark.parametrize(
    ("filename", "expected_name", "expected_extension"),
    [
        ("../../report.pdf", "report.pdf", ".pdf"),
        (r"C:\\temp\\image.png", "image.png", ".png"),
        ("..\\..\\avatar.gif", "avatar.gif", ".gif"),
    ],
)
def test_normalize_upload_filename_strips_path_components(
    filename: str, expected_name: str, expected_extension: str
) -> None:
    assert api.normalize_upload_filename(filename) == (expected_name, expected_extension)


@pytest.mark.parametrize("filename", ["", None, "../../", "no-extension", "hidden.exe"])
def test_normalize_upload_filename_rejects_invalid_names(filename: str | None) -> None:
    with pytest.raises(HTTPException) as exc:
        api.normalize_upload_filename(filename)
    assert exc.value.status_code == 400


def test_upload_signature_and_mime_validation() -> None:
    assert api.validate_upload_signature(".pdf", b"%PDF-1.7")
    assert not api.validate_upload_signature(".pdf", b"GIF89a")
    assert api.content_type_matches_extension(".png", "image/png")
    assert not api.content_type_matches_extension(".png", "text/html")


def _fake_request_config(tmp_path, monkeypatch, max_size_mb=1):
    config = AppConfig(
        messaging=MessagingConfig(
            max_file_size_mb=max_size_mb,
            allowed_file_types=[".jpg", ".png", ".gif", ".pdf", ".doc", ".docx", ".txt"],
        )
    )
    monkeypatch.setattr(api, "get_config", lambda: config)
    monkeypatch.chdir(tmp_path)


def _result(value):
    return SimpleNamespace(
        scalar_one_or_none=lambda: value,
        scalars=lambda: SimpleNamespace(all=lambda: [value] if value else []),
    )


def _upload_file(filename: str, content_type: str, contents: bytes) -> UploadFile:
    return UploadFile(
        filename=filename,
        file=io.BytesIO(contents),
        headers={"content-type": content_type},
    )


@pytest.mark.security
def test_upload_rejects_oversized_file_while_streaming(tmp_path, monkeypatch) -> None:
    _fake_request_config(tmp_path, monkeypatch, max_size_mb=1)
    chat = SimpleNamespace(id="chat-1", is_active=True, members=[SimpleNamespace(user_id="user-1")])
    db = AsyncMock()
    db.execute.return_value = _result(chat)
    contents = b"%PDF-" + b"A" * (1024 * 1024 + 10)
    read_sizes = []
    class TrackingUploadFile(UploadFile):
        async def read(self, size: int = -1) -> bytes:
            read_sizes.append(size)
            return await super().read(size)

    file = TrackingUploadFile(
        filename="big.pdf",
        file=io.BytesIO(contents),
        headers={"content-type": "application/pdf"},
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.upload_file(file, "chat-1", db, SimpleNamespace(id="user-1")))

    assert exc.value.status_code == 413
    assert read_sizes and all(0 < size <= api.MAX_UPLOAD_CHUNK_BYTES for size in read_sizes)
    assert not list((tmp_path / "data" / "uploads").glob("*"))


@pytest.mark.security
def test_upload_rejects_extension_mime_signature_mismatch(tmp_path, monkeypatch) -> None:
    _fake_request_config(tmp_path, monkeypatch)
    chat = SimpleNamespace(id="chat-1", is_active=True, members=[SimpleNamespace(user_id="user-1")])
    db = AsyncMock()
    db.execute.return_value = _result(chat)
    file = _upload_file("avatar.png", "image/png", b"<html>not a png</html>")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.upload_file(file, "chat-1", db, SimpleNamespace(id="user-1")))

    assert exc.value.status_code == 400
    db.add.assert_not_called()
    assert not list((tmp_path / "data" / "uploads").glob("*"))


@pytest.mark.security
def test_upload_rejects_nonmember_before_reading_file(tmp_path, monkeypatch) -> None:
    _fake_request_config(tmp_path, monkeypatch)
    chat = SimpleNamespace(id="chat-1", is_active=True, members=[SimpleNamespace(user_id="other-user")])
    db = AsyncMock()
    db.execute.return_value = _result(chat)
    file = _upload_file("doc.pdf", "application/pdf", b"%PDF-1.7 content")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.upload_file(file, "chat-1", db, SimpleNamespace(id="user-1")))

    assert exc.value.status_code == 403
    assert file.file.tell() == 0
    db.add.assert_not_called()


@pytest.mark.security
def test_download_requires_current_chat_membership(tmp_path, monkeypatch) -> None:
    upload_dir = tmp_path / "data" / "uploads"
    upload_dir.mkdir(parents=True)
    stored = upload_dir / "file-1.pdf"
    stored.write_bytes(b"%PDF-1.7 example")
    record = SimpleNamespace(
        id="file-1",
        chat_id="chat-1",
        uploader_user_id="user-1",
        storage_key="file-1.pdf",
        original_name="report.pdf",
        content_type="application/pdf",
        size_bytes=17,
        sha256="0" * 64,
    )
    db = AsyncMock()
    db.execute.side_effect = [
        _result(record),
        _result(None),
    ]
    monkeypatch.chdir(tmp_path)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(api.download_file("file-1", db, SimpleNamespace(id="attacker")))

    assert exc.value.status_code == 403


@pytest.mark.security
def test_upload_scan_hook_rejects_missing_or_empty_storage(tmp_path) -> None:
    missing = str(tmp_path / "missing.pdf")
    assert not api.upload_scan_hook(missing, "application/pdf", "missing.pdf")
    empty = tmp_path / "empty.pdf"
    empty.write_bytes(b"")
    assert not api.upload_scan_hook(str(empty), "application/pdf", "empty.pdf")
