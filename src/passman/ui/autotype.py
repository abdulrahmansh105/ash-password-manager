"""Shared click -> confirm -> Auto-Type flow for manager and account details."""

import gi

gi.require_version("Adw", "1")
from gi.repository import Adw, GLib

from ..core.auth.async_login import run_blocking_async
from ..core.auth.detection import DetectedContext, focus_target_window, get_active_window_context
from ..core.auth.engine import LoginEngine, LoginOutcome, SafetyGuardMode
from ..core.auth.strategy import AuthStrategy
from ..input import select_backend


class AccountAutoType:
    def __init__(self, app) -> None:
        self.app = app
        self.busy = False

    def request(self, parent, entry_uuid: str, display_name: str) -> None:
        if self.busy or not self.app.session.is_unlocked():
            return
        context = getattr(self.app, "detected_context", None)
        if not isinstance(context, DetectedContext) or (
            context.app_id and context.app_id.startswith("dev.ash.PasswordManager")
        ):
            context = DetectedContext(None, None)
        remembered = bool(context.window_id)
        if remembered:
            instruction = (
                f"Type this account's credentials into {context.app_id or 'the previous window'}? "
                "ASH will return to that window and run the saved login sequence."
            )
        else:
            instruction = (
                "Type this account's credentials? After Yes, ASH will hide for 5 seconds. "
                "Switch to the login window and click its first field during that time."
            )
        confirm = Adw.AlertDialog(heading=f"Auto-Type {display_name}?", body=instruction)
        confirm.add_response("cancel", "Cancel")
        confirm.add_response("yes", "Yes")
        confirm.set_default_response("cancel")
        confirm.set_close_response("cancel")
        confirm.set_response_appearance("yes", Adw.ResponseAppearance.SUGGESTED)
        self.busy = True

        def finish(result=None):
            self.busy = False
            if not self.app.session.is_unlocked():
                return
            if result is not None and result.outcome is LoginOutcome.SUCCESS:
                # Keep the successful login in front. Reopening ASH refreshes
                # its target through the launcher's focus command.
                return
            if result is not None and result.outcome is LoginOutcome.NO_BACKEND:
                message = "No input method available. Enable ydotoold or AT-SPI."
            else:
                message = "Auto-Type stopped. Check the login window and try again."
            parent._toast_overlay.add_toast(Adw.Toast(title=message))
            parent.present()

        def work():
            if not self.app.session.is_unlocked():
                return None
            target = context if remembered else get_active_window_context()
            if not target.app_id and not target.window_id:
                raise RuntimeError("target window unavailable")
            if target.app_id and target.app_id.startswith("dev.ash.PasswordManager"):
                raise RuntimeError("cannot type into the password manager")
            if remembered and not focus_target_window(target):
                raise RuntimeError("target window could not be restored")
            backend = select_backend(
                allow_clipboard_fallback=self.app.settings.clipboard_fallback_enabled,
                clipboard=self.app.session.clipboard,
                clear_after_seconds=self.app.settings.clipboard_timeout_seconds(),
            )
            if not self.app.session.is_unlocked():
                return None
            with self.app.session.vault().get_account_secrets(entry_uuid) as secrets:
                return LoginEngine(backend).run(
                    secrets, AuthStrategy.from_json(secrets.auth_strategy_json), target,
                    SafetyGuardMode(self.app.settings.safety_guard_mode), confirmed=True,
                    is_cancelled=lambda: not self.app.session.is_unlocked(),
                    context_provider=get_active_window_context,
                )

        def start_worker():
            if not self.app.session.is_unlocked():
                self.busy = False
                return False
            run_blocking_async(work, finish, on_error=lambda _: finish())
            return False

        def on_response(_dialog, response):
            if response != "yes" or not self.app.session.is_unlocked():
                self.busy = False
                return
            parent.set_visible(False)
            GLib.timeout_add(250 if remembered else 5000, start_worker)

        confirm.connect("response", on_response)
        confirm.present(parent)


def request_autotype(app, parent, entry_uuid: str, display_name: str) -> None:
    controller = getattr(app, "_account_autotype", None)
    if controller is None:
        controller = app._account_autotype = AccountAutoType(app)
    controller.request(parent, entry_uuid, display_name)
