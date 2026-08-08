# -*- coding: utf-8 -*-
from __future__ import print_function

from javax.swing import (
    JPanel, JLabel, JTextField, JButton, JCheckBox, JComboBox,
    JScrollPane, JTable, JOptionPane, SwingUtilities, BorderFactory,
    ListSelectionModel
)
from javax.swing.table import DefaultTableModel
from javax.swing.border import EmptyBorder
from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Font, Color, FlowLayout
import threading

from core.batch_mapper import scan_proxy_history, get_history_hosts
from ui.components.rounded_border import RoundedBorder, _roundedCompound


class BatchMapperTab(JPanel):
    """
    Clean Suite Tab component for scanning Burp Proxy HTTP History by Domain in batch,
    correlating requests with Frida logs, and mapping sign field orders per endpoint.
    """

    def __init__(self, extender):
        JPanel.__init__(self, BorderLayout(10, 10))
        self._extender = extender
        self._callbacks = extender._callbacks
        self._helpers = extender._helpers
        self.setBorder(EmptyBorder(10, 10, 10, 10))

        self._scan_results = []
        self._buildUI()

    def _buildUI(self):
        # ---------------------------------------------------------------------
        # Top Panel: Filters and Controls
        # ---------------------------------------------------------------------
        topPanel = JPanel(GridBagLayout())
        topPanel.setBorder(_roundedCompound(radius=8, padding=10))

        gbc = GridBagConstraints()
        gbc.insets = Insets(4, 4, 4, 4)
        gbc.fill = GridBagConstraints.HORIZONTAL

        # Row 0: Target Domain & Refresh
        gbc.gridy = 0; gbc.gridx = 0; gbc.weightx = 0.0
        topPanel.add(JLabel("Target Domain:"), gbc)

        gbc.gridx = 1; gbc.weightx = 0.35
        self._domainCombo = JComboBox(["(All Domains)"])
        self._domainCombo.setToolTipText("Select or filter by unique hostnames detected in Burp HTTP History")
        topPanel.add(self._domainCombo, gbc)

        gbc.gridx = 2; gbc.weightx = 0.0
        self._refreshDomainsBtn = JButton("Refresh", actionPerformed=self._onRefreshDomains)
        self._refreshDomainsBtn.setToolTipText("Scan HTTP History to populate target domains")
        topPanel.add(self._refreshDomainsBtn, gbc)

        gbc.gridx = 3; gbc.weightx = 0.0
        topPanel.add(JLabel("URL Pattern:"), gbc)

        gbc.gridx = 4; gbc.weightx = 0.35
        self._urlFilterText = JTextField("*")
        self._urlFilterText.setToolTipText("Filter by path pattern (e.g. *api* or regex pattern)")
        topPanel.add(self._urlFilterText, gbc)

        # Row 1: Frida Log Path, Scope, Method
        gbc.gridy = 1; gbc.gridx = 0; gbc.weightx = 0.0
        topPanel.add(JLabel("Frida Log Path:"), gbc)

        gbc.gridx = 1; gbc.weightx = 0.35
        self._logPathText = JTextField("/tmp/cipherkit_frida.log")
        self._logPathText.setToolTipText("Path to Frida log file")
        topPanel.add(self._logPathText, gbc)

        gbc.gridx = 2; gbc.weightx = 0.0
        self._inScopeChk = JCheckBox("In-Scope", False)
        self._inScopeChk.setToolTipText("Restrict scanning to Burp target scope only")
        topPanel.add(self._inScopeChk, gbc)

        gbc.gridx = 3; gbc.weightx = 0.0
        topPanel.add(JLabel("Methods:"), gbc)

        gbc.gridx = 4; gbc.weightx = 0.35
        self._methodFilterText = JTextField("POST, PUT")
        self._methodFilterText.setToolTipText("Comma-separated methods to scan (e.g. POST, PUT, ALL)")
        topPanel.add(self._methodFilterText, gbc)

        # Row 2: Control Buttons (Standard Clean Text)
        gbc.gridy = 2; gbc.gridx = 0; gbc.gridwidth = 5; gbc.weightx = 1.0
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))

        self._scanBtn = JButton("Scan History & Map Sign Orders", actionPerformed=self._onScanHistory)
        self._scanBtn.setFont(Font("SansSerif", Font.BOLD, 12))
        self._createAppSettingBtn = JButton("Save as AppSetting Profile", actionPerformed=self._onCreateAppSetting)
        self._createAppSettingBtn.setEnabled(False)
        self._clearBtn = JButton("Clear", actionPerformed=self._onClear)

        btnPanel.add(self._scanBtn)
        btnPanel.add(self._createAppSettingBtn)
        btnPanel.add(self._clearBtn)
        topPanel.add(btnPanel, gbc)
        gbc.gridwidth = 1  # restore

        # ---------------------------------------------------------------------
        # Center Panel: Full Height Results Table (Clean layout)
        # ---------------------------------------------------------------------
        # ---------------------------------------------------------------------
        # Center Panel: Full Height Results Table (Clean layout)
        # ---------------------------------------------------------------------
        self._tableModel = DefaultTableModel(
            ["#", "Host / Domain", "Endpoint URL Path", "Detected Sign Order", "Hash Match"], 0
        )
        self._table = JTable(self._tableModel)
        self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
        self._table.setFont(Font("SansSerif", Font.PLAIN, 12))
        self._table.setRowHeight(24)
        self._table.getSelectionModel().addListSelectionListener(lambda e: self._onTableSelectionChange(e))

        # Column widths
        self._table.getColumnModel().getColumn(0).setPreferredWidth(40)   # #
        self._table.getColumnModel().getColumn(1).setPreferredWidth(180)  # Host
        self._table.getColumnModel().getColumn(2).setPreferredWidth(280)  # Endpoint
        self._table.getColumnModel().getColumn(3).setPreferredWidth(340)  # Sign Order
        self._table.getColumnModel().getColumn(4).setPreferredWidth(120)  # Hash Match

        tableScroll = JScrollPane(self._table)
        tableScroll.setBorder(BorderFactory.createTitledBorder("Mapped Endpoint Sign Orders"))

        # Status Bar
        self._statusLabel = JLabel("Ready. Select a target domain or click 'Scan History & Map Sign Orders'.")
        self._statusLabel.setBorder(EmptyBorder(4, 4, 4, 4))

        self.add(topPanel, BorderLayout.NORTH)
        self.add(tableScroll, BorderLayout.CENTER)
        self.add(self._statusLabel, BorderLayout.SOUTH)

        # Populate domain dropdown
        SwingUtilities.invokeLater(lambda: self._onRefreshDomains())

    def _onRefreshDomains(self, event=None):
        """Populate target domain dropdown from Burp Proxy History."""
        try:
            hosts = get_history_hosts(self._callbacks, self._helpers)
            current = str(self._domainCombo.getSelectedItem()) if self._domainCombo.getItemCount() > 0 else "(All Domains)"
            self._domainCombo.removeAllItems()
            for h in hosts:
                self._domainCombo.addItem(h)
            if current in hosts:
                self._domainCombo.setSelectedItem(current)
            else:
                self._domainCombo.setSelectedIndex(0)
            self._statusLabel.setText("Refreshed target domains (%d domains found)." % (len(hosts) - 1))
        except Exception as e:
            print("[CipherKit] Error refreshing domains: %s" % str(e))

    def _onScanHistory(self, event=None):
        """Run history scanning in a background thread."""
        self._scanBtn.setEnabled(False)
        self._statusLabel.setText("Scanning Proxy HTTP History & Frida log...")

        domain_filter = str(self._domainCombo.getSelectedItem()) if self._domainCombo.getItemCount() > 0 else "(All Domains)"
        url_filter = self._urlFilterText.getText().strip()
        method_filter = self._methodFilterText.getText().strip()
        only_in_scope = self._inScopeChk.isSelected()
        log_path = self._logPathText.getText().strip()
        outer = self

        def run_scan():
            try:
                results = scan_proxy_history(
                    callbacks=outer._callbacks,
                    helpers=outer._helpers,
                    domain_filter=domain_filter,
                    url_filter=url_filter,
                    method_filter=method_filter,
                    only_in_scope=only_in_scope,
                    log_path=log_path,
                    max_items=500
                )
                
                def update_swing():
                    matched_results = [res for res in results if res.get("status") == "MATCHED" and res.get("sign_order")]
                    outer._scan_results = matched_results
                    outer._tableModel.setRowCount(0)

                    for idx, res in enumerate(matched_results, 1):
                        outer._tableModel.addRow([
                            idx,
                            res.get("host", ""),
                            res["url_path"],
                            res["sign_order"],
                            res.get("hash_match", "N/A")
                        ])

                    msg = "Scan complete. Discovered %d verified endpoint sign orders." % len(matched_results)
                    outer._statusLabel.setText(msg)
                    outer._scanBtn.setEnabled(True)
                    if len(matched_results) > 0:
                        outer._createAppSettingBtn.setEnabled(True)

                SwingUtilities.invokeLater(update_swing)
            except Exception as e:
                def update_err():
                    outer._statusLabel.setText("Scan error: %s" % str(e))
                    outer._scanBtn.setEnabled(True)
                SwingUtilities.invokeLater(update_err)

        t = threading.Thread(target=run_scan)
        t.daemon = True
        t.start()

    def _onTableSelectionChange(self, event):
        if event.getValueIsAdjusting():
            return
        row = self._table.getSelectedRow()
        if row >= 0 and row < len(self._scan_results):
            res = self._scan_results[row]
            self._createAppSettingBtn.setEnabled(bool(res.get("sign_order")))

    def _onCreateAppSetting(self, event=None):
        if not self._scan_results:
            return

        # Find selected row or save all matched
        row = self._table.getSelectedRow()
        target_results = [self._scan_results[row]] if (row >= 0 and row < len(self._scan_results)) else self._scan_results
        matched_items = [r for r in target_results if r.get("status") == "MATCHED" and r.get("sign_order")]

        if not matched_items:
            JOptionPane.showMessageDialog(self, "No endpoints with detected sign orders to save.", "Warning", JOptionPane.WARNING_MESSAGE)
            return

        sample_host = matched_items[0].get("host", "")
        asm = self._extender.app_setting_manager
        existing_names = asm.get_all_names()
        default_app_name = "ABA Mobile" if "ABA Mobile" in existing_names else (sample_host if sample_host else "MappedApp")

        app_name = JOptionPane.showInputDialog(
            self,
            "Save %d Endpoint Sign Orders to AppSetting Profile:\n\nEnter Profile Name (Existing or New):" % len(matched_items),
            default_app_name
        )
        if not app_name or not app_name.strip():
            return
        app_name = app_name.strip()

        try:
            # Ensure base app profile exists
            if not asm.get_app(app_name):
                asm.save_app(app_name, {
                    "algorithm": "SHA-256",
                    "secret": "",
                    "custom_data": {},
                    "hash_field": "hash",
                    "endpoints": {}
                })

            added_count = 0
            for res in matched_items:
                url_path = res["url_path"]
                sign_order = res["sign_order"]
                pattern = url_path if url_path.endswith("*") else url_path
                asm.save_endpoint(app_name, pattern, sign_order)
                added_count += 1

            # Refresh settings UI
            try:
                self._extender.show_main_app_setting(app_name)
            except Exception:
                pass

            JOptionPane.showMessageDialog(
                self,
                "Successfully saved %d endpoint sign orders into AppSetting profile '%s'!" % (added_count, app_name),
                "AppSetting Saved",
                JOptionPane.INFORMATION_MESSAGE
            )
        except Exception as e:
            JOptionPane.showMessageDialog(self, "Error creating AppSetting: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)


    def _onClear(self, event=None):
        self._scan_results = []
        self._tableModel.setRowCount(0)
        self._statusLabel.setText("Cleared results.")
        self._createAppSettingBtn.setEnabled(False)
