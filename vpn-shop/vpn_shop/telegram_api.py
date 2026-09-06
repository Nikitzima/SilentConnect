from __future__ import annotations

import json
import mimetypes
from pathlib import Path
import secrets
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class TelegramApiError(RuntimeError):
    pass


class TelegramBotClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise TelegramApiError("TELEGRAM_BOT_TOKEN is not configured")
        self.base_url = f"https://api.telegram.org/bot{token}/"

    def _call(self, method: str, payload: dict[str, Any] | None = None) -> Any:
        data = None
        headers = {
            "Accept": "application/json",
            "User-Agent": "vpn-shop/0.1",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"

        request = urllib.request.Request(
            urllib.parse.urljoin(self.base_url, method),
            data=data,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise TelegramApiError(f"HTTP {exc.code} for {method}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise TelegramApiError(f"Telegram request failed for {method}: {exc}") from exc

        parsed = json.loads(raw.decode("utf-8"))
        if not parsed.get("ok"):
            raise TelegramApiError(parsed.get("description") or f"Telegram API error in {method}")
        return parsed["result"]

    def _call_multipart(
        self,
        method: str,
        fields: dict[str, Any],
        *,
        file_field: str,
        file_path: Path,
    ) -> Any:
        boundary = f"----vpnshop{secrets.token_hex(16)}"
        body_parts: list[bytes] = []

        for name, value in fields.items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                rendered = json.dumps(value, ensure_ascii=False)
            elif isinstance(value, bool):
                rendered = "true" if value else "false"
            else:
                rendered = str(value)
            body_parts.extend(
                [
                    f"--{boundary}\r\n".encode("ascii"),
                    f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("ascii"),
                    rendered.encode("utf-8"),
                    b"\r\n",
                ]
            )

        filename = file_path.name.replace('"', "")
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        body_parts.extend(
            [
                f"--{boundary}\r\n".encode("ascii"),
                (
                    f'Content-Disposition: form-data; name="{file_field}"; '
                    f'filename="{filename}"\r\n'
                ).encode("ascii"),
                f"Content-Type: {content_type}\r\n\r\n".encode("ascii"),
                file_path.read_bytes(),
                b"\r\n",
                f"--{boundary}--\r\n".encode("ascii"),
            ]
        )

        request = urllib.request.Request(
            urllib.parse.urljoin(self.base_url, method),
            data=b"".join(body_parts),
            headers={
                "Accept": "application/json",
                "User-Agent": "vpn-shop/0.1",
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise TelegramApiError(f"HTTP {exc.code} for {method}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise TelegramApiError(f"Telegram request failed for {method}: {exc}") from exc

        parsed = json.loads(raw.decode("utf-8"))
        if not parsed.get("ok"):
            raise TelegramApiError(parsed.get("description") or f"Telegram API error in {method}")
        return parsed["result"]

    def get_updates(self, offset: int | None = None, timeout: int = 30) -> list[dict[str, Any]]:
        payload: dict[str, Any] = {"timeout": timeout}
        if offset is not None:
            payload["offset"] = offset
        return self._call("getUpdates", payload)

    def send_message(
        self,
        chat_id: int | str,
        text: str,
        *,
        reply_markup: dict[str, Any] | None = None,
        protect_content: bool = False,
        disable_web_page_preview: bool = True,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "protect_content": protect_content,
            "link_preview_options": {"is_disabled": disable_web_page_preview},
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._call("sendMessage", payload)

    def send_photo(
        self,
        chat_id: int | str,
        photo: str,
        *,
        caption: str = "",
        reply_markup: dict[str, Any] | None = None,
        protect_content: bool = False,
    ) -> dict[str, Any]:
        photo_path = Path(photo).expanduser()
        if photo_path.is_file():
            fields: dict[str, Any] = {
                "chat_id": chat_id,
                "caption": caption,
                "protect_content": protect_content,
            }
            if reply_markup is not None:
                fields["reply_markup"] = reply_markup
            return self._call_multipart("sendPhoto", fields, file_field="photo", file_path=photo_path)

        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "photo": photo,
            "caption": caption,
            "protect_content": protect_content,
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._call("sendPhoto", payload)

    def send_document(
        self,
        chat_id: int | str,
        document: str | Path,
        *,
        caption: str = "",
        protect_content: bool = False,
    ) -> dict[str, Any]:
        doc_path = Path(document).expanduser()
        fields: dict[str, Any] = {
            "chat_id": chat_id,
            "caption": caption,
            "protect_content": protect_content,
        }
        return self._call_multipart("sendDocument", fields, file_field="document", file_path=doc_path)

    def edit_message_text(
        self,
        *,
        chat_id: int | str,
        message_id: int,
        text: str,
        reply_markup: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": text,
            "link_preview_options": {"is_disabled": True},
        }
        if reply_markup is not None:
            payload["reply_markup"] = reply_markup
        return self._call("editMessageText", payload)

    def answer_callback_query(self, callback_query_id: str, text: str = "", show_alert: bool = False) -> bool:
        payload = {
            "callback_query_id": callback_query_id,
            "text": text,
            "show_alert": show_alert,
        }
        return bool(self._call("answerCallbackQuery", payload))

    def delete_message(self, chat_id: int | str, message_id: int) -> bool:
        payload = {
            "chat_id": chat_id,
            "message_id": int(message_id),
        }
        try:
            return bool(self._call("deleteMessage", payload))
        except Exception:
            return False
