"""Auto-Type / Auth Strategy editor -- visual, ordered step list, no
JSON editing required (spec requirement). Wraps the pure editing model
in ``core.auth.strategy_editor`` and never itself contains editing
logic beyond GTK glue, so every add/remove/reorder/validate rule is
covered by that module's own toolkit-free tests.

Security posture, matching the incident this feature exists to prevent:
- "Test Strategy" NEVER uses the account's real password/TOTP -- see
  ``core.auth.test_run``. It runs the real Safety Guard against the
  real detected target, so an ambiguous/unknown target still requires
  confirmation here exactly as it would for a real run.
- Nothing in this file can render a password/TOTP/recovery-code value;
  ``AuthStep`` has no field that could hold one.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gtk

from ..core.auth.async_login import run_blocking_async
from ..core.auth.detection import get_active_window_context
from ..core.auth.engine import LoginOutcome, SafetyGuardMode
from ..core.auth.strategy import (
    BUILTIN_STRATEGIES,
    DEFAULT_STRATEGY,
    AuthStep,
    AuthStrategy,
    StepAction,
)
from ..core.auth.strategy_editor import (
    STEP_LABELS,
    add_step,
    duplicate_step,
    matches_preset,
    move_step,
    preview_text,
    remove_step,
    toggle_enabled,
    update_step,
    validate_strategy,
)
from ..core.auth.strategy_presets import load_custom_presets, save_custom_preset
from ..core.auth.test_run import run_test
from ..input import select_backend

_ACTION_ORDER = [
    StepAction.TYPE_USERNAME,
    StepAction.TYPE_PASSWORD,
    StepAction.TYPE_TOTP,
    StepAction.KEY_TAB,
    StepAction.KEY_ENTER,
    StepAction.KEY_ESCAPE,
    StepAction.KEY_COMBO,
    StepAction.WAIT,
    StepAction.FOCUS_FIELD,
]


class StrategyStepRow(Gtk.Box):
    """One editable row. Value-editing widgets shown depend on the
    step's action -- WAIT gets a bounded spin button, KEY_COMBO gets a
    validated entry, FOCUS_FIELD gets a field-hint entry plus an
    AT-SPI-required warning; the rest need no extra field."""

    def __init__(self, index: int, step: AuthStep, editor: StrategyEditorDialog) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        self.add_css_class("card")
        self.set_margin_top(4)
        self.set_margin_bottom(4)

        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        top.set_margin_top(8)
        top.set_margin_bottom(4)
        top.set_margin_start(10)
        top.set_margin_end(10)

        action_list = Gtk.StringList.new([STEP_LABELS[a] for a in _ACTION_ORDER])
        dropdown = Gtk.DropDown(model=action_list, selected=_ACTION_ORDER.index(step.action))
        dropdown.set_hexpand(True)
        dropdown.connect("notify::selected", lambda dd, _p: editor._on_action_changed(index, _ACTION_ORDER[dd.get_selected()]))
        top.append(dropdown)

        enabled_switch = Gtk.Switch(active=step.enabled, valign=Gtk.Align.CENTER)
        enabled_switch.set_tooltip_text("Enabled")
        enabled_switch.connect("notify::active", lambda sw, _p: editor._on_toggle_enabled(index))
        top.append(enabled_switch)

        for icon, tooltip, handler in (
            ("go-up-symbolic", "Move up", lambda _b: editor._on_move(index, -1)),
            ("go-down-symbolic", "Move down", lambda _b: editor._on_move(index, 1)),
            ("edit-copy-symbolic", "Duplicate", lambda _b: editor._on_duplicate(index)),
            ("user-trash-symbolic", "Delete", lambda _b: editor._on_remove(index)),
        ):
            btn = Gtk.Button.new_from_icon_name(icon)
            btn.add_css_class("flat")
            btn.set_tooltip_text(tooltip)
            btn.connect("clicked", handler)
            top.append(btn)

        self.append(top)

        extra = self._build_value_field(step, index, editor)
        if extra is not None:
            extra.set_margin_start(10)
            extra.set_margin_end(10)
            extra.set_margin_bottom(8)
            self.append(extra)

    def _build_value_field(self, step: AuthStep, index: int, editor: StrategyEditorDialog):
        if step.action == StepAction.WAIT:
            box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
            box.append(Gtk.Label(label="Milliseconds:"))
            adjustment = Gtk.Adjustment(
                value=int(step.value or "0"), lower=0, upper=30_000, step_increment=100
            )
            spin = Gtk.SpinButton(adjustment=adjustment, numeric=True)
            spin.connect("value-changed", lambda s: editor._on_update(index, value=str(int(s.get_value()))))
            box.append(spin)
            return box

        if step.action == StepAction.KEY_COMBO:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            entry = Gtk.Entry(text=step.value or "", placeholder_text="e.g. ctrl+v")
            entry.connect("changed", lambda e: editor._on_update(index, value=e.get_text()))
            box.append(entry)
            hint = Gtk.Label(label="modifier+key, lowercase (ctrl/shift/alt + a letter or digit)", xalign=0)
            hint.add_css_class("pm-hint-label")
            box.append(hint)
            return box

        if step.action == StepAction.FOCUS_FIELD:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            entry = Gtk.Entry(text=step.field_hint or "", placeholder_text="field hint, e.g. password")
            entry.connect("changed", lambda e: editor._on_update(index, field_hint=e.get_text()))
            box.append(entry)
            warn = Gtk.Label(
                label="Requires AT-SPI (accessibility) support on the target -- not guaranteed to "
                "work on apps that don't expose an accessibility tree. Falls back to no-op, "
                "not an error, if unsupported.",
                xalign=0,
                wrap=True,
            )
            warn.add_css_class("pm-hint-label")
            box.append(warn)
            return box

        return None


class StrategyEditorDialog(Adw.Dialog):
    def __init__(
        self,
        app,
        entry_uuid: str,
        display_name: str,
        service_name: str,
        account_has_totp: bool,
        account_has_username: bool,
        account_has_password: bool,
        app_identifiers: tuple[str, ...],
        on_saved,
    ) -> None:
        super().__init__(title="Auto-Type Strategy", content_width=520, content_height=640)
        self._app = app
        self._entry_uuid = entry_uuid
        self._display_name = display_name
        self._service_name = service_name
        self._account_has_totp = account_has_totp
        self._account_has_username = account_has_username
        self._account_has_password = account_has_password
        self._app_identifiers = app_identifiers
        self._on_saved = on_saved

        raw = app.session.vault().get_auth_strategy_json(entry_uuid)
        self._strategy_name = AuthStrategy.from_json(raw).name
        self._steps: tuple[AuthStep, ...] = AuthStrategy.from_json(raw).steps

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(Adw.HeaderBar())
        self.set_child(toolbar_view)

        outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        outer.set_margin_top(16)
        outer.set_margin_bottom(16)
        outer.set_margin_start(16)
        outer.set_margin_end(16)

        # -- preset selector ---------------------------------------------
        preset_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        preset_box.append(Gtk.Label(label="Preset:"))
        self._preset_names = ["Default", "Multi-page", "Password-only", "Custom"]
        self._custom_preset_names = list(load_custom_presets().keys())
        self._preset_names += self._custom_preset_names
        self._preset_dropdown = Gtk.DropDown(model=Gtk.StringList.new(self._preset_names))
        self._preset_dropdown.set_hexpand(True)
        self._preset_dropdown.connect("notify::selected", self._on_preset_selected)
        preset_box.append(self._preset_dropdown)
        save_preset_btn = Gtk.Button(label="Save as preset")
        save_preset_btn.connect("clicked", self._on_save_as_preset)
        preset_box.append(save_preset_btn)
        outer.append(preset_box)

        # -- preview -------------------------------------------------------
        self._preview_label = Gtk.Label(xalign=0, wrap=True)
        self._preview_label.add_css_class("pm-hint-label")
        outer.append(self._preview_label)

        # -- validation banner ----------------------------------------------
        self._validation_label = Gtk.Label(xalign=0, wrap=True)
        self._validation_label.add_css_class("pm-error-label")
        self._validation_label.set_visible(False)
        outer.append(self._validation_label)

        # -- step list -----------------------------------------------------
        scroller = Gtk.ScrolledWindow(vexpand=True)
        self._steps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        scroller.set_child(self._steps_box)
        outer.append(scroller)

        add_btn = Gtk.Button(label="+ Add Step")
        add_btn.connect("clicked", self._on_add_step)
        outer.append(add_btn)

        # -- test strategy ---------------------------------------------------
        test_btn = Gtk.Button(label="Test Strategy (fake credentials only)")
        test_btn.connect("clicked", self._on_test_strategy)
        outer.append(test_btn)
        self._test_result_label = Gtk.Label(xalign=0, wrap=True, selectable=True)
        outer.append(self._test_result_label)

        toolbar_view.set_content(outer)

        bottom_bar = Adw.HeaderBar(show_start_title_buttons=False, show_end_title_buttons=False, show_title=False)
        cancel_btn = Gtk.Button(label="Cancel")
        cancel_btn.connect("clicked", lambda _b: self.close())
        bottom_bar.pack_start(cancel_btn)
        self._save_btn = Gtk.Button(label="Save")
        self._save_btn.add_css_class("suggested-action")
        self._save_btn.connect("clicked", self._on_save)
        bottom_bar.pack_end(self._save_btn)
        toolbar_view.add_bottom_bar(bottom_bar)

        self._sync_preset_selector_to_steps()
        self._render()

    # -- rendering -----------------------------------------------------------

    def _render(self) -> None:
        child = self._steps_box.get_first_child()
        while child is not None:
            nxt = child.get_next_sibling()
            self._steps_box.remove(child)
            child = nxt
        for i, step in enumerate(self._steps):
            self._steps_box.append(StrategyStepRow(i, step, self))

        self._preview_label.set_text(preview_text(self._steps))

        problems = validate_strategy(
            self._steps,
            account_has_totp=self._account_has_totp,
            account_has_username=self._account_has_username,
            account_has_password=self._account_has_password,
        )
        if problems:
            self._validation_label.set_text("\n".join(problems))
            self._validation_label.set_visible(True)
            self._save_btn.set_sensitive(False)
        else:
            self._validation_label.set_visible(False)
            self._save_btn.set_sensitive(True)

    def _sync_preset_selector_to_steps(self) -> None:
        for name, builtin in (("Default", DEFAULT_STRATEGY), ("Multi-page", BUILTIN_STRATEGIES.get("multi_page")), ("Password-only", BUILTIN_STRATEGIES.get("password_only"))):
            if builtin is not None and matches_preset(self._steps, builtin):
                self._preset_dropdown.set_selected(self._preset_names.index(name))
                return
        for name, custom in load_custom_presets().items():
            if matches_preset(self._steps, custom) and name in self._preset_names:
                self._preset_dropdown.set_selected(self._preset_names.index(name))
                return
        self._preset_dropdown.set_selected(self._preset_names.index("Custom"))

    # -- step list edit callbacks ---------------------------------------------

    def _on_action_changed(self, index: int, new_action: StepAction) -> None:
        self._steps = update_step(self._steps, index, action=new_action)
        self._render()

    def _on_toggle_enabled(self, index: int) -> None:
        self._steps = toggle_enabled(self._steps, index)
        self._render()

    def _on_move(self, index: int, direction: int) -> None:
        self._steps = move_step(self._steps, index, direction)
        self._render()

    def _on_duplicate(self, index: int) -> None:
        self._steps = duplicate_step(self._steps, index)
        self._render()

    def _on_remove(self, index: int) -> None:
        self._steps = remove_step(self._steps, index)
        self._render()

    def _on_update(self, index: int, **changes: object) -> None:
        self._steps = update_step(self._steps, index, **changes)
        self._render()

    def _on_add_step(self, _btn) -> None:
        self._steps = add_step(self._steps, AuthStep(action=StepAction.KEY_TAB))
        self._render()

    # -- presets ------------------------------------------------------------

    def _on_preset_selected(self, dropdown: Gtk.DropDown, _param) -> None:
        name = self._preset_names[dropdown.get_selected()]
        preset_map = {"Default": DEFAULT_STRATEGY, "Multi-page": BUILTIN_STRATEGIES.get("multi_page"), "Password-only": BUILTIN_STRATEGIES.get("password_only")}
        strategy = preset_map.get(name)
        if strategy is None and name != "Custom":
            strategy = load_custom_presets().get(name)
        if strategy is not None:
            self._steps = strategy.steps
            self._render()

    def _on_save_as_preset(self, _btn) -> None:
        dialog = Adw.AlertDialog(heading="Save as preset", body="Name this preset:")
        entry = Gtk.Entry()
        dialog.set_extra_child(entry)
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("save", "Save")
        dialog.set_response_appearance("save", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_d, response):
            if response == "save" and entry.get_text().strip():
                name = entry.get_text().strip()
                save_custom_preset(name, AuthStrategy(name=name, steps=self._steps))
                if name not in self._preset_names:
                    self._preset_names.append(name)
                    self._preset_dropdown.set_model(Gtk.StringList.new(self._preset_names))
                self._preset_dropdown.set_selected(self._preset_names.index(name))

        dialog.connect("response", on_response)
        dialog.present(self)

    # -- test strategy --------------------------------------------------------

    def _on_test_strategy(self, _btn) -> None:
        # Active-window detection (a `hyprctl` subprocess call), backend
        # selection (an AT-SPI probe / ydotool `pgrep`), and the test run
        # itself (subprocess calls, WAIT-step sleeps) all block -- none of
        # them may run on this (GTK main) thread. See
        # core.auth.async_login for why; this handler hands the whole
        # thing to a background thread and returns immediately.
        strategy = AuthStrategy(name=self._strategy_name, steps=self._steps)
        clipboard_fallback = self._app.settings.clipboard_fallback_enabled
        guard_mode = SafetyGuardMode(self._app.settings.safety_guard_mode)
        self._test_result_label.set_text("Testing strategy…")

        def work():
            context = get_active_window_context()
            backend = select_backend(allow_clipboard_fallback=clipboard_fallback)
            result = run_test(
                backend,
                strategy,
                context,
                guard_mode,
                entry_uuid=self._entry_uuid,
                display_name=self._display_name,
                service_name=self._service_name,
                app_identifiers=self._app_identifiers,
                include_totp=self._account_has_totp,
                confirmed=False,
            )
            return context, result

        def on_done(payload) -> None:
            context, result = payload
            if result.outcome == LoginOutcome.NEEDS_CONFIRMATION:
                self._show_test_confirmation(strategy, context)
                return
            self._render_test_result(result)

        run_blocking_async(work, on_done)

    def _show_test_confirmation(self, strategy: AuthStrategy, context) -> None:
        window_desc = context.app_id or context.window_title or "an unrecognized window"
        confirm = Adw.AlertDialog(
            heading="Ambiguous target",
            body=(
                f"The current target ({window_desc}) doesn't match this account's known "
                "app identifiers with high confidence. Test anyway with FAKE credentials "
                "(never the real password/TOTP)?"
            ),
        )
        confirm.add_response("cancel", "Cancel")
        confirm.add_response("test", "Test with fake credentials")
        confirm.set_response_appearance("test", Adw.ResponseAppearance.SUGGESTED)

        def on_response(_d, response):
            if response != "test":
                return
            clipboard_fallback = self._app.settings.clipboard_fallback_enabled
            guard_mode = SafetyGuardMode(self._app.settings.safety_guard_mode)
            self._test_result_label.set_text("Testing strategy…")

            def work():
                backend = select_backend(allow_clipboard_fallback=clipboard_fallback)
                return run_test(
                    backend,
                    strategy,
                    context,
                    guard_mode,
                    entry_uuid=self._entry_uuid,
                    display_name=self._display_name,
                    service_name=self._service_name,
                    app_identifiers=self._app_identifiers,
                    include_totp=self._account_has_totp,
                    confirmed=True,
                )

            run_blocking_async(work, self._render_test_result)

        confirm.connect("response", on_response)
        confirm.present(self)

    def _render_test_result(self, result) -> None:
        lines = [
            f"Target: confidence={result.confidence.value}, guard={result.guard_decision.value}",
            f"Outcome: {result.outcome.value} ({result.detail})",
        ]
        for report in result.steps:
            lines.append(f"  {'OK' if report.ok else 'FAILED'}  {report.label}")
        self._test_result_label.set_text("\n".join(lines))

    # -- save ------------------------------------------------------------------

    def _on_save(self, _btn) -> None:
        strategy = AuthStrategy(name=self._strategy_name, steps=self._steps)
        vault = self._app.session.vault()
        vault.update_account_fields(self._entry_uuid, auth_strategy_json=strategy.to_json())
        vault.save()
        self._on_saved()
        self.close()
