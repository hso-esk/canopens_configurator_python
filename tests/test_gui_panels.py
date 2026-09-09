"""CONFIGURATOR_REQUIREMENTS.md §11 E: GUI panel tests, driven under a hidden Tk root via injectable callbacks.
Needs a display; skip cleanly when none (run under xvfb-run otherwise).
"""

import os
import unittest

_NO_DISPLAY = not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY")

if not _NO_DISPLAY:
    try:
        import tkinter as tk
        from spsec_configurator.gui.device_panel import DevicePanel, DeviceDisplayInfo
        from spsec_configurator.gui.group_panel import GroupPanel, GroupDisplayInfo
        from spsec_configurator.gui.operations_panel import OperationsPanel
    except Exception:  # pragma: no cover - tkinter present but unusable
        _NO_DISPLAY = True


@unittest.skipIf(_NO_DISPLAY, "no display available (run under xvfb-run)")
class _PanelTestCase(unittest.TestCase):
    """Hidden Tk root shared by the panel tests."""

    def setUp(self):
        self.root = tk.Tk()
        self.root.withdraw()

    def tearDown(self):
        self.root.update_idletasks()
        self.root.destroy()


class TestDevicePanel(_PanelTestCase):
    """TC-CFG-030: device tree populates from a discovery result."""

    def test_set_devices_populates_tree(self):
        panel = DevicePanel(self.root)
        panel.set_devices([
            DeviceDisplayInfo(participant_id=120, core_version="0.34",
                              mapping_version="302-1.40", status=0x04),
            DeviceDisplayInfo(participant_id=121, core_version="0.34",
                              mapping_version="302-1.40", status=0x04),
            DeviceDisplayInfo(participant_id=122, core_version="0.34",
                              mapping_version="302-1.40", status=0x01),
        ])
        self.root.update_idletasks()

        tree = panel.tree
        self.assertEqual(len(tree.get_children()), 3)
        rendered = " ".join(str(tree.item(i)) for i in tree.get_children())
        for pid in (120, 121, 122):
            self.assertIn(str(pid), rendered)

    def test_clear_devices_empties_tree(self):
        panel = DevicePanel(self.root)
        panel.set_devices([DeviceDisplayInfo(participant_id=120)])
        self.root.update_idletasks()
        self.assertEqual(len(panel.tree.get_children()), 1)

        panel.clear_devices()
        self.root.update_idletasks()
        self.assertEqual(len(panel.tree.get_children()), 0)

    def test_refresh_callback_is_invoked(self):
        fired = []
        panel = DevicePanel(self.root, on_refresh=lambda: fired.append(True))
        panel._on_refresh_click()
        self.assertEqual(fired, [True])


class TestGroupPanel(_PanelTestCase):
    """TC-CFG-031: creating a group surfaces through the panel callback."""

    def test_set_groups_populates_tree(self):
        panel = GroupPanel(self.root)
        panel.set_groups([
            GroupDisplayInfo(group_id=1, name="DriveGroup",
                             description="Emergency Stop", member_pids=[120, 121],
                             has_keys=True),
        ])
        self.root.update_idletasks()

        tree = panel.group_tree
        self.assertEqual(len(tree.get_children()), 1)
        self.assertIn("DriveGroup", str(tree.item(tree.get_children()[0])))

    def test_create_callback_is_invoked(self):
        fired = []
        panel = GroupPanel(self.root, on_group_create=lambda: fired.append(True))
        panel._on_create_click()
        self.assertEqual(fired, [True])

    def test_delete_callback_receives_selected_group(self):
        received = []
        panel = GroupPanel(self.root, on_group_delete=received.append)
        panel.set_groups([GroupDisplayInfo(group_id=7, name="Doomed")])
        self.root.update_idletasks()

        tree = panel.group_tree
        tree.selection_set(tree.get_children()[0])
        panel._on_group_select(None)
        panel._on_delete_click()

        self.assertEqual(received, [7])


class TestOperationsPanel(_PanelTestCase):
    """TC-CFG-032: the batch/bootstrap panel constructs and exposes its tabs."""

    def test_panel_constructs(self):
        panel = OperationsPanel(self.root)
        self.root.update_idletasks()
        self.assertTrue(panel.winfo_exists())

    def test_rekey_seed_button_invokes_callback(self):
        """Seed rotation needs its own GUI action - bootstrap also writes the
        write-once Integrator key, so it can't be reused for this."""
        seen = {}

        def on_rekey_seed(pid, keys):
            seen["pid"] = pid
            seen["keys"] = keys

        panel = OperationsPanel(self.root, on_rekey_seed=on_rekey_seed)
        self.root.update_idletasks()

        panel.bootstrap_pid_entry.delete(0, "end")
        panel.bootstrap_pid_entry.insert(0, "120")
        panel.key_source_var.set("file")
        panel.rekey_seed_btn.invoke()

        self.assertEqual(seen.get("pid"), 120)

    def test_provision_discovered_batch_option_invokes_callback(self):
        """The scan-then-provision flow must be selectable in Batch Operations."""
        seen = {}

        def on_provision_discovered(pids, keys):
            seen["pids"] = pids

        panel = OperationsPanel(
            self.root, on_provision_discovered=on_provision_discovered)
        self.root.update_idletasks()

        panel.batch_pids_entry.delete(0, "end")
        panel.batch_pids_entry.insert(0, "120-122")
        panel.batch_op_var.set("provision_discovered")
        panel.batch_key_source_var.set("file")
        panel._on_batch_click()

        self.assertEqual(seen.get("pids"), [120, 121, 122])

    def test_no_seed_session_offered_anywhere(self):
        """Seed key must not appear as a session-key choice - the participant
        refuses it in select_base_key(), so offering it would only fail."""
        panel = OperationsPanel(self.root)
        self.root.update_idletasks()
        values = panel.initial_key_selector_combo.cget("values")
        joined = " ".join(str(v) for v in values)
        self.assertNotIn("Seed", joined)
        self.assertNotIn("13", joined)


if __name__ == "__main__":
    unittest.main()
