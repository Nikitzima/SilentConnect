from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.message import EmailMessage
from email.headerregistry import Address
import html
import json
import logging
import os
from pathlib import Path
import queue
import smtplib
import threading
from typing import Any
import urllib.error
import urllib.request

from .config import Settings

LOGGER = logging.getLogger("vpn-shop-mailer")

_EMAIL_QUEUE: queue.Queue[tuple[Any, tuple, dict] | None] = queue.Queue(maxsize=1000)
_EMAIL_WORKERS: list[threading.Thread] = []
_EMAIL_WORKERS_LOCK = threading.Lock()
NUM_EMAIL_WORKERS = 4


def _email_worker_loop() -> None:
    while True:
        try:
            item = _EMAIL_QUEUE.get()
            if item is None:
                _EMAIL_QUEUE.task_done()
                break
            func, args, kwargs = item
            try:
                func(*args, **kwargs)
            except Exception as exc:
                LOGGER.exception("Unhandled error in email worker: %s", exc)
            finally:
                _EMAIL_QUEUE.task_done()
        except Exception:
            pass


def _ensure_workers_started() -> None:
    with _EMAIL_WORKERS_LOCK:
        alive = [w for w in _EMAIL_WORKERS if w.is_alive()]
        _EMAIL_WORKERS.clear()
        _EMAIL_WORKERS.extend(alive)
        while len(_EMAIL_WORKERS) < NUM_EMAIL_WORKERS:
            t = threading.Thread(target=_email_worker_loop, daemon=True)
            t.start()
            _EMAIL_WORKERS.append(t)


def enqueue_email_task(func: Any, *args: Any, **kwargs: Any) -> bool:
    """Enqueue an email dispatch task to the bounded background worker pool."""
    _ensure_workers_started()
    try:
        _EMAIL_QUEUE.put_nowait((func, args, kwargs))
        return True
    except queue.Full:
        LOGGER.error("Email worker queue is full (maxsize=1000). Dropping email task: %s", getattr(func, "__name__", str(func)))
        return False

MONTHS_RU = [
    "", "января", "февраля", "марта", "апреля", "мая", "июня",
    "июля", "августа", "сентября", "октября", "ноября", "декабря"
]


def format_expiry_ru(duration_days: int, expires_ts: int | float | None = None, expires_str: str = "") -> str:
    if expires_str.strip():
        return expires_str.strip()
    try:
        if expires_ts and isinstance(expires_ts, (int, float)) and expires_ts > 0:
            dt = datetime.fromtimestamp(expires_ts, tz=timezone.utc)
        else:
            dt = datetime.now(timezone.utc) + timedelta(days=duration_days)
        return f"{dt.day} {MONTHS_RU[dt.month]} {dt.year} г."
    except Exception:
        return f"+{duration_days} дн."


def render_subscription_email_html(
    *,
    customer_email: str,
    order_public_id: str,
    plan_name: str,
    duration_days: int,
    setup_url: str,
    json_url: str,
    cabinet_url: str,
    bind_tg_url: str = "",
    expires_ts: int | float | None = None,
    expires_at_str: str = "",
    support_email: str = "support@example.com",
    support_tg: str = "https://t.me/your_support",
) -> str:
    expiry_display = format_expiry_ru(duration_days, expires_ts, expires_at_str)
    tg_target_url = bind_tg_url or os.environ.get("SUPPORT_TG_URL", "https://t.me/your_support_bot")
    tg_btn_label = "Привязать к Telegram-боту ✈️" if bind_tg_url else "Открыть Telegram-бота ✈️"
    tg_bind_box = f"""
      <div class="box" style="text-align: center;">
        <h3 style="color: #ffffff; font-size: 16px; margin-top: 0;">✈️ &nbsp;Удобное управление в Telegram:</h3>
        <p style="margin-bottom: 15px;">Управляйте подпиской и продлевайте доступ прямо в нашем Telegram-боте:</p>
        <div style="text-align: center; margin: 10px 0;">
          <a href="{tg_target_url}" class="btn" style="background-color: #0088cc; padding: 12px 24px; font-size: 15px; border-radius: 8px; font-weight: bold;">{tg_btn_label}</a>
        </div>
      </div>
    """

    clean_setup_url = setup_url.split("?")[0]
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Ваша подписка SilentConnect</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #050a08;
      color: #f4f7f5;
      margin: 0;
      padding: 20px;
    }}
    .container {{
      max-width: 600px;
      margin: 0 auto;
      background-color: #14231c;
      border: 1px solid #2fbf71;
      border-radius: 12px;
      padding: 4px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }}
    .titlebar {{
      background: linear-gradient(90deg, #14231c 0%, #2fbf71 100%);
      color: #ffffff;
      font-weight: bold;
      padding: 12px 18px;
      font-size: 16px;
      border-radius: 8px 8px 0 0;
      letter-spacing: 0.3px;
    }}
    .content {{
      padding: 20px;
      background-color: #0a1410;
      border-radius: 0 0 8px 8px;
    }}
    .box {{
      background-color: #14231c;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 16px;
    }}
    .summary-card {{
      background-color: rgba(47, 191, 113, 0.08);
      border: 1px solid rgba(47, 191, 113, 0.3);
      border-radius: 8px;
      padding: 16px 18px;
      margin-bottom: 18px;
    }}
    .summary-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    .summary-table td {{
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.06);
    }}
    .summary-table tr:last-child td {{
      border-bottom: none;
    }}
    h2 {{
      margin-top: 0;
      color: #2fbf71;
      font-size: 20px;
    }}
    h3 {{
      margin-top: 0;
      color: #ffffff;
      font-size: 16px;
    }}
    p {{
      line-height: 1.5;
      font-size: 14px;
      color: #8ea89a;
    }}
    .btn {{
      display: inline-block;
      background-color: #2fbf71;
      color: #000000 !important;
      text-decoration: none;
      font-weight: bold;
      padding: 14px 28px;
      border-radius: 8px;
      font-size: 16px;
      text-align: center;
      box-shadow: 0 4px 12px rgba(47, 191, 113, 0.3);
    }}
    .footer {{
      margin-top: 20px;
      font-size: 12px;
      color: #8ea89a;
      border-top: 1px solid rgba(255,255,255,0.1);
      padding-top: 12px;
    }}
    .code-box {{
      background-color: #050a08;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: monospace;
      word-break: break-all;
      font-size: 12px;
      color: #2fbf71;
    }}
    .code-box a {{
      color: #2fbf71;
      text-decoration: none;
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="titlebar">
      🔑 &nbsp;SilentConnect &nbsp;&nbsp;·&nbsp;&nbsp; Подписка готова
    </div>
    <div class="content">
      <h2>Благодарим за покупку! 🎉</h2>
      <p style="margin-bottom: 16px;">Оплата заказа <strong>#{order_public_id}</strong> успешно подтверждена. Информация о вашей подписке:</p>
      
      <div class="summary-card">
        <h3 style="color: #2fbf71; font-size: 15px; margin-bottom: 12px; margin-top: 0;">📋 Детали операции:</h3>
        <table class="summary-table" role="presentation">
          <tr>
            <td style="color: #8ea89a;">Статус:</td>
            <td style="text-align: right; color: #2fbf71; font-weight: bold;">Оплачено и активно ✅</td>
          </tr>
          <tr>
            <td style="color: #8ea89a;">Продление:</td>
            <td style="text-align: right; color: #ffffff; font-weight: bold;">+ {duration_days} дней</td>
          </tr>
          <tr>
            <td style="color: #8ea89a;">Действительна до:</td>
            <td style="text-align: right; color: #2fbf71; font-weight: bold;">{expiry_display}</td>
          </tr>
          <tr>
            <td style="color: #8ea89a;">Лимит устройств:</td>
            <td style="text-align: right; color: #ffffff; font-weight: bold;">3 устройства</td>
          </tr>
        </table>
      </div>

      <div class="box" style="text-align: center; padding: 22px 16px;">
        <h3>💻 Личный кабинет подписки и подключение:</h3>
        <p style="margin-bottom: 18px;">Нажмите кнопку ниже, чтобы открыть мастера подключения (Happ, Streisand, V2RayTun), смотреть статистику и продлевать доступ:</p>
        <div style="text-align: center; margin: 15px 0;">
          <a href="{clean_setup_url}" class="btn">Открыть Личный Кабинет 💻</a>
        </div>
      </div>

      {tg_bind_box}

      <div class="box">
        <h3>🔗 Прямые ссылки на подписку:</h3>
        <p style="margin-bottom: 6px;">Прямая ссылка для импорта в приложение:</p>
        <div class="code-box"><a href="{clean_setup_url}">{clean_setup_url}</a></div>
        
        <p style="margin-top: 14px; margin-bottom: 6px; color:#ffffff; font-weight: bold; font-size: 13px;">Прямой формат JSON (для кастомных клиентов):</p>
        <div class="code-box"><a href="{json_url}">{json_url}</a></div>
      </div>

      <div class="footer">
        <p>Нужна помощь? Напишите нам на почту <a href="mailto:{support_email}" style="color:#2fbf71;">{support_email}</a> или в Telegram: <a href="{support_tg}" style="color:#2fbf71;">{support_tg}</a>.</p>
        <p>© SilentConnect. Все права защищены.</p>
      </div>
    </div>
  </div>
</body>
</html>
"""


def render_subscription_email_text(
    *,
    customer_email: str,
    order_public_id: str,
    plan_name: str,
    duration_days: int,
    setup_url: str,
    json_url: str,
    cabinet_url: str,
    bind_tg_url: str = "",
    support_email: str = "support@example.com",
    support_tg: str = "https://t.me/your_support",
) -> str:
    bind_line = f"\nПривязать подписку к Telegram-боту: {bind_tg_url}\n" if bind_tg_url else ""
    return f"""Благодарим за покупку в SilentConnect!

Оплата заказа #{order_public_id} успешно подтверждена.
Ваша подписка: {plan_name} ({duration_days} дней).

1. Ссылка для импорта в приложение (Happ / Streisand / V2RayTun):
{setup_url}
{bind_line}
2. Прямой формат JSON:
{json_url}

3. Личный кабинет подписки и продление:
{cabinet_url}

Поддержка: {support_email} | Telegram: {support_tg}
"""


def render_expiration_reminder_email_html(
    *,
    customer_email: str,
    reminder_kind: str,
    setup_url: str,
    support_email: str = "support@example.com",
    support_tg: str = "https://t.me/your_support",
) -> str:
    time_label = "завтра (через 24 часа)" if reminder_kind == "1_day" else "уже через 1 час"
    urgent_tag = "⏳ Напоминание о продлении" if reminder_kind == "1_day" else "🚨 Срочно: скорое отключение"

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>Срок действия подписки SilentConnect истекает</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: #050a08; color: #f4f7f5; margin: 0; padding: 20px; }}
    .container {{ max-width: 600px; margin: 0 auto; background-color: #14231c; border: 1px solid #2fbf71; border-radius: 12px; padding: 20px; }}
    h2 {{ color: #2fbf71; margin-top: 0; }}
    p {{ color: #8ea89a; line-height: 1.5; font-size: 15px; }}
    .btn {{ display: inline-block; background-color: #2fbf71; color: #000000 !important; text-decoration: none; font-weight: bold; padding: 14px 28px; border-radius: 8px; font-size: 16px; margin: 15px 0; }}
    .footer {{ margin-top: 20px; font-size: 12px; color: #8ea89a; border-top: 1px solid rgba(255,255,255,0.1); padding-top: 10px; }}
  </style>
</head>
<body>
  <div class="container">
    <h2>{urgent_tag}</h2>
    <p>Здравствуйте!</p>
    <p>Напоминаем, что срок действия вашей подписки SilentConnect истекает <strong>{time_label}</strong>.</p>
    <p>Чтобы доступ к сети не прерывался, вы можете продлить подписку прямо сейчас в один клик в вашем личном кабинете:</p>
    <div style="text-align: center;">
      <a href="{setup_url}" class="btn">Продлить подписку на сайте</a>
    </div>
    <p>При продлении ваш текущий адрес подключения и настройки в приложении сохранятся без необходимости перенастройки.</p>
    <div class="footer">
      <p>Служба поддержки SilentConnect: <a href="mailto:{support_email}" style="color:#2fbf71;">{support_email}</a> | <a href="{support_tg}" style="color:#2fbf71;">Telegram</a></p>
    </div>
  </div>
</body>
</html>
"""


def render_expiration_reminder_email_text(
    *,
    customer_email: str,
    reminder_kind: str,
    setup_url: str,
    support_email: str = "support@example.com",
    support_tg: str = "https://t.me/your_support",
) -> str:
    time_label = "завтра (через 24 часа)" if reminder_kind == "1_day" else "уже через 1 час"
    return f"""Здравствуйте!

Напоминаем, что срок действия вашей подписки SilentConnect истекает {time_label}.

Продлить подписку без смены ссылок и настроек вы можете в личном кабинете:
{setup_url}

Служба поддержки: {support_email} | Telegram: {support_tg}
"""


def send_subscription_email_sync(
    settings: Settings,
    *,
    customer_email: str,
    order_public_id: str,
    plan_name: str,
    duration_days: int,
    setup_url: str,
    json_url: str,
    cabinet_url: str,
    bind_tg_url: str = "",
    expires_ts: int | float | None = None,
    expires_at_str: str = "",
    subject: str | None = None,
) -> bool:
    if not customer_email or "@" not in customer_email:
        LOGGER.warning("Invalid target email for order %s: %r", order_public_id, customer_email)
        return False

    smtp_host = (settings.smtp_host or "").strip()
    if not smtp_host:
        LOGGER.info(
            "SMTP host not configured. Email dispatch skipped for order %s to %s (Setup URL: %s)",
            order_public_id,
            customer_email,
            setup_url,
        )
        return False

    port = settings.smtp_port or 465
    user = (settings.smtp_user or "").strip()
    password = (settings.smtp_password or "").strip()
    from_email = (settings.smtp_from_email or "SilentConnect <support@example.com>").strip()

    if not subject:
        subject = f"Ваша подписка SilentConnect готова! (#{order_public_id})"

    html_content = render_subscription_email_html(
        customer_email=customer_email,
        order_public_id=order_public_id,
        plan_name=plan_name,
        duration_days=duration_days,
        setup_url=setup_url,
        json_url=json_url,
        cabinet_url=cabinet_url,
        bind_tg_url=bind_tg_url,
        expires_ts=expires_ts,
        expires_at_str=expires_at_str,
        support_email=settings.support_email or "support@example.com",
        support_tg=settings.support_tg_url or "https://t.me/your_support",
    )
    text_content = render_subscription_email_text(
        customer_email=customer_email,
        order_public_id=order_public_id,
        plan_name=plan_name,
        duration_days=duration_days,
        setup_url=setup_url,
        json_url=json_url,
        cabinet_url=cabinet_url,
        bind_tg_url=bind_tg_url,
    )

    resend_api_key = password if password.startswith("re_") else (user if user.startswith("re_") else "")
    if resend_api_key or "resend" in smtp_host.lower():
        api_key = resend_api_key or password
        try:
            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=json.dumps({
                    "from": from_email,
                    "to": [customer_email],
                    "subject": subject,
                    "html": html_content,
                    "text": text_content,
                }).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                LOGGER.info("Subscription email sent via Resend API to %s for order %s (ID: %s)", customer_email, order_public_id, resp_data.get("id"))
                return True
        except Exception as exc:
            LOGGER.exception("Failed to send subscription email via Resend API to %s for order %s: %s", customer_email, order_public_id, exc)
            return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = customer_email

    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    try:
        if port == 465:
            with smtplib.SMTP_SSL(smtp_host, port, timeout=10) as server:
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=10) as server:
                server.ehlo()
                server.starttls()
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        LOGGER.info("Subscription email successfully sent to %s for order %s", customer_email, order_public_id)
        return True
    except Exception as exc:
        LOGGER.exception("Failed to send subscription email to %s for order %s: %s", customer_email, order_public_id, exc)
        return False


def send_subscription_email_async(
    settings: Settings,
    *,
    customer_email: str,
    order_public_id: str,
    plan_name: str,
    duration_days: int,
    setup_url: str,
    json_url: str,
    cabinet_url: str,
    bind_tg_url: str = "",
    expires_ts: int | float | None = None,
    expires_at_str: str = "",
    subject: str | None = None,
) -> None:
    enqueue_email_task(
        send_subscription_email_sync,
        settings,
        customer_email=customer_email,
        order_public_id=order_public_id,
        plan_name=plan_name,
        duration_days=duration_days,
        setup_url=setup_url,
        json_url=json_url,
        cabinet_url=cabinet_url,
        bind_tg_url=bind_tg_url,
        expires_ts=expires_ts,
        expires_at_str=expires_at_str,
        subject=subject,
    )


def build_cabinet_access_email_html(
    *,
    customer_email: str,
    profiles_data: list[dict[str, Any]],
    support_email: str = "support@example.com",
    support_tg: str = "https://t.me/your_support",
    cabinet_url: str = "",
    default_device_limit: int = 3,
) -> tuple[str, str]:
    """Returns (subject, html_content) for cabinet access email."""
    target_cabinet_url = (cabinet_url or "").strip()
    if not target_cabinet_url and profiles_data:
        target_cabinet_url = str(profiles_data[0].get("setup_url") or "").strip()
    if not target_cabinet_url:
        target_cabinet_url = "https://example.com/"

    profiles_count = len(profiles_data)
    if profiles_count == 1:
        profile_word = "подписка"
    elif 2 <= profiles_count <= 4:
        profile_word = "подписки"
    else:
        profile_word = "подписок"

    items_html = ""
    for idx, p in enumerate(profiles_data, 1):
        expires_at = p.get("expires_at")
        expires_str = format_expiry_ru(0, expires_ts=expires_at) if expires_at else "---"
        device_limit = int(p.get("device_limit") or default_device_limit)
        transport_raw = str(p.get("transport") or "tcp")
        transport_lbl = "Гибридный" if "hybrid" in transport_raw else ("TCP / Reality" if transport_raw == "tcp" else "XHTTP")

        items_html += f"""
        <div class="sub-item">
          <table class="item-table" role="presentation">
            <tr>
              <td style="color: #ffffff; font-weight: bold; padding: 2px 0;">
                🔑 Подписка #{idx}
              </td>
              <td class="col-meta" style="text-align: right; color: #8ea89a; font-size: 12px; padding: 2px 0;">
                до {device_limit} устр. · {transport_lbl}
              </td>
            </tr>
            <tr>
              <td style="color: #8ea89a; font-size: 13px; padding-top: 4px;">Срок действия:</td>
              <td class="col-expiry" style="text-align: right; color: #2fbf71; font-weight: bold; font-size: 13px; padding-top: 4px;">до {expires_str}</td>
            </tr>
          </table>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Вход в личный кабинет SilentConnect</title>
  <style>
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: #050a08;
      color: #f4f7f5;
      margin: 0;
      padding: 20px 10px;
    }}
    .container {{
      max-width: 600px;
      margin: 0 auto;
      background-color: #14231c;
      border: 1px solid #2fbf71;
      border-radius: 12px;
      padding: 4px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }}
    .titlebar {{
      background: linear-gradient(90deg, #14231c 0%, #2fbf71 100%);
      color: #ffffff;
      font-weight: bold;
      padding: 12px 18px;
      font-size: 16px;
      border-radius: 8px 8px 0 0;
      letter-spacing: 0.3px;
    }}
    .content {{
      padding: 20px;
      background-color: #0a1410;
      border-radius: 0 0 8px 8px;
    }}
    .box {{
      background-color: #14231c;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 8px;
      padding: 18px;
      margin-bottom: 16px;
    }}
    .summary-card {{
      background-color: rgba(47, 191, 113, 0.08);
      border: 1px solid rgba(47, 191, 113, 0.3);
      border-radius: 8px;
      padding: 16px 18px;
      margin-bottom: 18px;
    }}
    .sub-item {{
      background-color: #14231c;
      border: 1px solid rgba(255,255,255,0.08);
      border-radius: 8px;
      padding: 12px 14px;
      margin-bottom: 10px;
    }}
    .sub-item:last-child {{
      margin-bottom: 0;
    }}
    .item-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13.5px;
    }}
    h2 {{
      margin-top: 0;
      color: #2fbf71;
      font-size: 20px;
    }}
    h3 {{
      margin-top: 0;
      color: #ffffff;
      font-size: 16px;
    }}
    p {{
      line-height: 1.5;
      font-size: 14px;
      color: #8ea89a;
    }}
    .btn {{
      display: inline-block;
      background-color: #2fbf71;
      color: #000000 !important;
      text-decoration: none;
      font-weight: bold;
      padding: 14px 28px;
      border-radius: 8px;
      font-size: 16px;
      text-align: center;
      box-shadow: 0 4px 12px rgba(47, 191, 113, 0.3);
    }}
    .code-box {{
      background-color: #050a08;
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 6px;
      padding: 10px 12px;
      font-family: monospace;
      word-break: break-all;
      font-size: 12px;
      color: #2fbf71;
    }}
    .code-box a {{
      color: #2fbf71;
      text-decoration: none;
    }}
    .footer {{
      margin-top: 20px;
      font-size: 12px;
      color: #8ea89a;
      border-top: 1px solid rgba(255,255,255,0.1);
      padding-top: 12px;
    }}
    @media only screen and (max-width: 480px) {{
      body {{ padding: 10px 6px; }}
      .content {{ padding: 16px 12px; }}
      .item-table td {{ display: block !important; width: 100% !important; text-align: left !important; }}
      .item-table td.col-meta {{ text-align: left !important; padding-top: 2px !important; color: #8ea89a !important; }}
      .item-table td.col-expiry {{ text-align: left !important; padding-top: 2px !important; }}
      .btn {{ display: block !important; width: 100% !important; box-sizing: border-box !important; padding: 14px 12px !important; font-size: 15px !important; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <div class="titlebar">
      🔑 &nbsp;SilentConnect &nbsp;&nbsp;·&nbsp;&nbsp; Личный кабинет
    </div>
    <div class="content">
      <h2>Вход в личный кабинет 🔐</h2>
      <p style="margin-bottom: 16px;">По вашему запросу для <strong>{html.escape(customer_email)}</strong> сформирован доступ к управлению подписками.</p>

      <div class="summary-card">
        <h3 style="color: #2fbf71; font-size: 15px; margin-bottom: 12px; margin-top: 0;">📋 Активные подписки ({profiles_count}):</h3>
        {items_html}
      </div>

      <div class="box" style="text-align: center; padding: 22px 16px;">
        <h3>💻 Управление подписками:</h3>
        <p style="margin-bottom: 18px;">Нажмите кнопку ниже, чтобы войти в личный кабинет, выбрать нужный профиль, подключить устройства или продлить доступ:</p>
        <div style="text-align: center; margin: 15px 0;">
          <a href="{html.escape(target_cabinet_url, quote=True)}" class="btn" target="_blank">
            Войти в Личный Кабинет 💻
          </a>
        </div>
      </div>

      <div class="box" style="text-align: center; margin-bottom: 16px;">
        <p style="margin: 0; font-size: 13px; color: #ffffff; line-height: 1.5;">
          ⏱ <strong>Ссылка активна в течение 30 минут</strong>.<br>
          <span style="color: #8ea89a; font-size: 12px;">В течение этого времени вы можете открывать её повторно с любого своего устройства (ПК, смартфон, планшет).</span>
        </p>
      </div>

      <div class="box">
        <h3>🔗 Прямая ссылка для входа:</h3>
        <p style="margin-bottom: 6px;">Если кнопка выше не открывается, скопируйте ссылку напрямую в браузер:</p>
        <div class="code-box">
          <a href="{html.escape(target_cabinet_url, quote=True)}">{html.escape(target_cabinet_url)}</a>
        </div>
      </div>

      <div class="footer">
        <p>Если вы не запрашивали доступ, просто проигнорируйте это письмо. Ваши данные в безопасности.</p>
        <p>Нужна помощь? Напишите нам на почту <a href="mailto:{html.escape(support_email)}" style="color:#2fbf71;">{html.escape(support_email)}</a> или в Telegram: <a href="{html.escape(support_tg, quote=True)}" style="color:#2fbf71;">{html.escape(support_tg)}</a>.</p>
        <p>© SilentConnect. Все права защищены.</p>
      </div>
    </div>
  </div>
</body>
</html>
"""

    subject = f"🔐 Вход в личный кабинет SilentConnect ({profiles_count} {profile_word})"
    return subject, html_content


def send_cabinet_access_email_sync(
    settings: Settings,
    *,
    customer_email: str,
    profiles_data: list[dict[str, Any]],
    cabinet_url: str = "",
) -> bool:
    if not settings.smtp_host or not customer_email:
        return False

    target_cabinet_url = (cabinet_url or "").strip()
    if not target_cabinet_url and profiles_data:
        target_cabinet_url = str(profiles_data[0].get("setup_url") or "").strip()
    if not target_cabinet_url:
        target_cabinet_url = f"{settings.web_public_base_url}/"

    profiles_count = len(profiles_data)
    subject, html_content = build_cabinet_access_email_html(
        customer_email=customer_email,
        profiles_data=profiles_data,
        support_email=settings.support_email or "support@example.com",
        support_tg=settings.support_tg_url or "https://t.me/your_support",
        cabinet_url=target_cabinet_url,
        default_device_limit=settings.default_device_limit,
    )
    from_email = settings.smtp_from_email or "SilentConnect <support@example.com>"
    smtp_host = settings.smtp_host or "smtp.resend.com"
    user = settings.smtp_user or "resend"
    password = settings.smtp_password or ""
    port = int(settings.smtp_port or 465)

    resend_api_key = password if password.startswith("re_") else (user if user.startswith("re_") else "")
    if resend_api_key or "resend" in smtp_host.lower():
        api_key = resend_api_key or password
        try:
            req = urllib.request.Request(
                "https://api.resend.com/emails",
                data=json.dumps({
                    "from": from_email,
                    "to": [customer_email],
                    "subject": subject,
                    "html": html_content,
                    "text": f"Ваши активные подписки SilentConnect ({profiles_count} шт.). Ссылка для входа в личный кабинет (действует 30 минут): {target_cabinet_url}",
                }).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
                LOGGER.info("Cabinet access email sent via Resend API to %s (ID: %s)", customer_email, resp_data.get("id"))
                return True
        except Exception as exc:
            LOGGER.exception("Failed to send cabinet email via Resend API to %s: %s", customer_email, exc)
            return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = customer_email
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    try:
        if port == 465:
            with smtplib.SMTP_SSL(smtp_host, port, timeout=15) as server:
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                if user and password:
                    server.login(user, password)
                server.send_message(msg)
        LOGGER.info("Cabinet access email sent to %s with %d profiles", customer_email, len(profiles_data))
        return True
    except Exception as exc:
        LOGGER.exception("Failed to send cabinet email to %s: %s", customer_email, exc)
        return False


def send_cabinet_access_email_async(
    settings: Settings,
    *,
    customer_email: str,
    profiles_data: list[dict[str, Any]],
    cabinet_url: str = "",
) -> None:
    enqueue_email_task(
        send_cabinet_access_email_sync,
        settings,
        customer_email=customer_email,
        profiles_data=profiles_data,
        cabinet_url=cabinet_url,
    )

