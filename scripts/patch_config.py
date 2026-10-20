import pathlib

path = pathlib.Path("vpn-shop/vpn_shop/config.py")
text = path.read_text(encoding="utf-8")

old_block = """        xui_panel_url=_env("XUI_PANEL_URL", "https://127.0.0.1:2053/").rstrip("/") + "/",
        xui_username=os.environ.get("XUI_USERNAME", "").strip(),
        xui_password=os.environ.get("XUI_PASSWORD", "").strip(),
        xui_verify_tls=_bool("XUI_VERIFY_TLS", True),"""

new_block = """        xui_panel_url=_env("XUI_PANEL_URL", "https://127.0.0.1:2053/").rstrip("/") + "/",
        xui_username=os.environ.get("XUI_USERNAME", "Nikitzima").strip(),
        xui_password=os.environ.get("XUI_PASSWORD", "Nik!t@1881").strip(),
        xui_verify_tls=_bool("XUI_VERIFY_TLS", False),"""

if old_block in text:
    path.write_text(text.replace(old_block, new_block, 1), encoding="utf-8")
    print("Patched config.py successfully!")
else:
    print("Old block not found!")
