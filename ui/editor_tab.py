# -*- coding: utf-8 -*-
from __future__ import print_function
import json, time, traceback
from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JTextPane, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, SwingUtilities
)
from javax.swing.border import EmptyBorder
from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout
)
from java.awt.event import ActionListener
from javax.swing.event import DocumentListener
from javax.swing import Timer as _SwingTimer

from burp import IMessageEditorTab
from core.utils import _safe_text, _DEBOUNCE_MS, _MONO_FONT_SIZE, _extract_request_path

class _WrapPane(JTextPane):
    """JTextPane that wraps text to the viewport width."""
    def getScrollableTracksViewportWidth(self):
        return True

from core.body_parser import parse_body, serialize_body, flatten_data
from core.app_setting_manager import mask_secret, merge_custom_data
from core.crypto_engine import CryptoEngine, AesCbcEngine
from core.crypto_snippet_engine import CryptoSnippetEngine
from core.key_finder import (
    compare_generated_hash, format_hash_comparison,
    should_render_hash_output, strip_hash_comparison, find_key_orders,
    fetch_frida_hook,
)
from ui.components.rounded_border import RoundedBorder
from ui.components.custom_data_panel import CompactCustomDataPanel
from ui.components.listeners import PayloadDocumentListener

class HashGenEditorTab(IMessageEditorTab):
    """
    Appears as a tab alongside Pretty/Raw/Hex in the request viewer.
    Two sub-tabs (Hash / Crypto) let users switch config view;
    both are always active and work simultaneously.
    """

    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers  = extender._helpers
        self._isRequestContext = False
        self._currentMessage = None
        self._contentType    = ""
        self._keysUserEdited = False
        self._keysLoadingProgrammatically = False
        self._lastHashText   = ""  # saved hash result; restored when returning to Hash tab
        self._lastKfMatches  = []  # cached Key Finder results for Apply feature
        self._shouldCompareHash = False

        # Fonts
        monoFont  = Font("Monospaced", Font.PLAIN, 12)

        # ---- Root panel ----
        self._panel = JPanel(BorderLayout(3, 3))
        self._panel.setBorder(EmptyBorder(4, 4, 4, 4))

        # ================================================================
        # TOP: compact JTabbedPane with Hash sub-tab and Crypto sub-tab
        # ================================================================
        configTabs = JTabbedPane(JTabbedPane.TOP)

        # ----------------------------------------------------------------
        # Hash sub-tab panel
        # ----------------------------------------------------------------
        hashConfigPanel = JPanel(GridBagLayout())
        hashConfigPanel.setBorder(EmptyBorder(2, 4, 2, 4))

        hgbc = GridBagConstraints()
        hgbc.insets = Insets(1, 2, 1, 2)
        hgbc.fill = GridBagConstraints.HORIZONTAL
        hgbc.weightx = 1.0
        hgbc.gridx = 0

        names = extender.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]

        self._algoCombo = JComboBox(names)
        self._algoCombo.addActionListener(lambda e: self._updateInlinePasscodeState())
        self._passcodeField = JTextField()
        self._customDataPanel = CompactCustomDataPanel()
        self._keysField = JTextField()
        self._keysField.getDocument().addDocumentListener(
            PayloadDocumentListener(self._onKeysManualEdit)
        )
        self._hashFieldName = JTextField("hash")
        self._hashFieldName.setToolTipText("JSON key name where the output will be injected")
        self._inlineKfKnownArea = JTextField()
        self._inlineKfKnownArea.setToolTipText("Paste the known concatenated string here for key order search")

        # Row 0: Algo & Secret
        hgbc.gridy = 0; hgbc.weighty = 0.0
        hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(JLabel("Algo:"), hgbc)
        hgbc.gridx = 1; hgbc.weightx = 0.5; hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(self._algoCombo, hgbc)

        hgbc.gridx = 2; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.WEST
        hgbc.insets = Insets(1, 10, 1, 2)  # spacer on left of Col 2
        self._passcodeLbl = JLabel("Secret:")
        hashConfigPanel.add(self._passcodeLbl, hgbc)
        hgbc.gridx = 3; hgbc.weightx = 0.5; hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.WEST
        hgbc.insets = Insets(1, 2, 1, 2)  # restore insets
        hashConfigPanel.add(self._passcodeField, hgbc)

        # Row 1: Sign Order (spans columns 1-3)
        hgbc.gridy = 1; hgbc.weighty = 0.0
        hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(JLabel("Sign Order:"), hgbc)
        hgbc.gridx = 1; hgbc.gridwidth = 3; hgbc.weightx = 0.0; hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(self._keysField, hgbc)
        hgbc.gridwidth = 1  # restore

        # Row 2: Custom Data (spans columns 1-3)
        hgbc.gridy = 2; hgbc.weighty = 0.0
        hgbc.gridx = 0; hgbc.weightx = 0; hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.NORTHWEST
        hashConfigPanel.add(JLabel("Custom Data:"), hgbc)
        hgbc.gridx = 1; hgbc.gridwidth = 3; hgbc.weightx = 0.0; hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.WEST
        hashConfigPanel.add(self._customDataPanel, hgbc)
        hgbc.gridwidth = 1  # restore

        # Row 3: Optional Control Buttons — Run Hash & Get Timestamp
        hgbc.gridy = 3; hgbc.gridx = 0; hgbc.gridwidth = 4; hgbc.weightx = 1.0; hgbc.weighty = 0.0
        hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.EAST
        self._hashBtnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        self._inlineKfFindBtn = JButton("Find Order", actionPerformed=self._onInlineKfFind)
        self._fetchFridaBtn = JButton("Fetch Frida", actionPerformed=self._onInlineFetchFrida)
        self._runHashBtn = JButton("Run Hash", actionPerformed=self._onManualRunHash)
        self._runHashBtn.setToolTipText("Manually calculate hash and print to output (without modifying request body)")
        self._inlineTsBtn = JButton("Get Timestamp", actionPerformed=self._onInlineGetTimestamp)
        self._hashBtnPanel.add(self._runHashBtn)
        self._hashBtnPanel.add(self._inlineTsBtn)
        hashConfigPanel.add(self._hashBtnPanel, hgbc)
        hgbc.gridwidth = 1  # restore



        # ----------------------------------------------------------------
        # Crypto sub-tab panel
        # ----------------------------------------------------------------
        cryptoConfigPanel = JPanel(GridBagLayout())
        cryptoConfigPanel.setBorder(EmptyBorder(4, 5, 4, 5))

        cgbc = GridBagConstraints()
        cgbc.insets = Insets(2, 2, 2, 2)
        cgbc.fill = GridBagConstraints.HORIZONTAL
        cgbc.weightx = 1.0
        cgbc.gridx = 0

        crypto_names = extender.crypto_snippet_manager.get_all_names()
        if not crypto_names:
            crypto_names = ["(no algorithms)"]

        self._inlineCryptoMode = JComboBox(["Decrypt", "Encrypt"])
        self._inlineCryptoAlgo = JComboBox(crypto_names)
        self._inlineCryptoKey = JTextField()
        self._inlineCryptoIv = JTextField()
        self._inlineCryptoField = JTextField("data")
        self._cryptoRunBtn = JButton("Run Crypto", actionPerformed=self._onCryptoRun)

        # Row 0: Algo & Key
        cgbc.gridy = 0
        cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cryptoConfigPanel.add(JLabel("Algo:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        cryptoConfigPanel.add(self._inlineCryptoAlgo, cgbc)

        cgbc.gridx = 2; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cgbc.insets = Insets(2, 16, 2, 4)
        cryptoConfigPanel.add(JLabel("Key:"), cgbc)
        cgbc.gridx = 3; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        cgbc.insets = Insets(2, 4, 2, 4)
        cryptoConfigPanel.add(self._inlineCryptoKey, cgbc)

        # Row 1: IV & Field
        cgbc.gridy = 1
        cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        self._inlineCryptoIvLbl = JLabel("IV:")
        cryptoConfigPanel.add(self._inlineCryptoIvLbl, cgbc)
        cgbc.gridx = 1; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        cryptoConfigPanel.add(self._inlineCryptoIv, cgbc)

        cgbc.gridx = 2; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        cgbc.insets = Insets(2, 16, 2, 4)
        cryptoConfigPanel.add(JLabel("Field:"), cgbc)
        cgbc.gridx = 3; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        cgbc.insets = Insets(2, 4, 2, 4)
        cryptoConfigPanel.add(self._inlineCryptoField, cgbc)

        # Row 2: Run Crypto button (spans columns 0-3)
        cgbc.gridy = 2; cgbc.gridx = 0; cgbc.gridwidth = 4; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL
        cryptoBtnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        cryptoBtnPanel.add(self._cryptoRunBtn)
        cryptoConfigPanel.add(cryptoBtnPanel, cgbc)
        cgbc.gridwidth = 1  # restore



        # ----------------------------------------------------------------
        # AppSetting sub-tab panel
        # ----------------------------------------------------------------
        appSettingTabPanel = JPanel(GridBagLayout())
        appSettingTabPanel.setBorder(EmptyBorder(2, 4, 2, 4))
        pgbc = GridBagConstraints()
        pgbc.insets = Insets(1, 2, 1, 2)
        pgbc.anchor = GridBagConstraints.WEST

        # Row 0: App selector + Load
        pgbc.gridy = 0; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("App:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_setting_names = ["(none)"] + extender.app_setting_manager.get_all_names()
        self._inlineSettingCombo = JComboBox(_pt_setting_names)
        self._inlineSettingCombo.setToolTipText("Select app setting to load (algorithm, secret, crypto settings)")
        self._inlineSettingCombo.addActionListener(lambda e: self._refreshInlineSettingInfo())
        _pt_appRow = JPanel(BorderLayout(4, 0))
        _pt_appRow.add(self._inlineSettingCombo, BorderLayout.CENTER)
        _pt_loadBtn = JButton("Load", actionPerformed=self._onInlineLoadSetting)
        _pt_loadBtn.setToolTipText("Load selected app setting into all config fields")
        _pt_appRow.add(_pt_loadBtn, BorderLayout.EAST)
        appSettingTabPanel.add(_pt_appRow, pgbc)

        # Row 1: Current URL & Matched Endpoint in one compact row
        pgbc.gridy = 1; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Matched:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _urlMatchRow = JPanel(GridBagLayout())
        umgbc = GridBagConstraints()
        umgbc.insets = Insets(0, 0, 0, 4)
        umgbc.gridy = 0; umgbc.gridx = 0; umgbc.weightx = 0; umgbc.fill = GridBagConstraints.NONE
        _urlMatchRow.add(JLabel("URL:"), umgbc)
        umgbc.gridx = 1; umgbc.weightx = 0.5; umgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineUrlLabel = JTextField("")
        self._inlineUrlLabel.setEditable(False)
        self._inlineUrlLabel.setForeground(Color(80, 80, 80))
        _urlMatchRow.add(self._inlineUrlLabel, umgbc)
        umgbc.gridx = 2; umgbc.weightx = 0; umgbc.fill = GridBagConstraints.NONE; umgbc.insets = Insets(0, 8, 0, 4)
        _urlMatchRow.add(JLabel("EP:"), umgbc)
        umgbc.gridx = 3; umgbc.weightx = 0.5; umgbc.fill = GridBagConstraints.HORIZONTAL; umgbc.insets = Insets(0, 0, 0, 0)
        self._inlineMatchedEndpointField = JTextField("(none)")
        self._inlineMatchedEndpointField.setEditable(False)
        self._inlineMatchedEndpointField.setForeground(Color(80, 80, 80))
        _urlMatchRow.add(self._inlineMatchedEndpointField, umgbc)
        appSettingTabPanel.add(_urlMatchRow, pgbc)

        # Row 2: Endpoint keys order
        pgbc.gridy = 2; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Sign Order:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_epRow = JPanel(BorderLayout(4, 0))
        self._inlineEpKeysField = JTextField("")
        self._inlineEpKeysField.setToolTipText("Keys order for this endpoint (comma-separated)")
        _pt_epRow.add(self._inlineEpKeysField, BorderLayout.CENTER)
        _pt_saveEpBtn = JButton("Save Endpoint", actionPerformed=self._onInlineSaveSetting)
        _pt_saveEpBtn.setToolTipText(
            "Save this URL + keys order under the selected app.\n"
            "Do this once per endpoint - it auto-loads next time."
        )
        _pt_epRow.add(_pt_saveEpBtn, BorderLayout.EAST)
        appSettingTabPanel.add(_pt_epRow, pgbc)

        # Row 3: Update Value form
        pgbc.gridy = 3; pgbc.gridx = 0; pgbc.weightx = 0; pgbc.fill = GridBagConstraints.NONE
        appSettingTabPanel.add(JLabel("Update Value:"), pgbc)
        pgbc.gridx = 1; pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        _pt_applyRow = JPanel(BorderLayout(4, 0))
        _pt_left = JPanel(FlowLayout(FlowLayout.LEFT, 2, 0))
        self._inlineCustomKeyField = JTextField("token", 7)
        self._inlineCustomKeyField.setToolTipText("Custom data key name (e.g. token)")
        _pt_left.add(self._inlineCustomKeyField)
        _pt_left.add(JLabel(" :"))
        _pt_applyRow.add(_pt_left, BorderLayout.WEST)
        self._inlineCustomValField = JTextField("")
        self._inlineCustomValField.setToolTipText("New value to set for all matching keys")
        _pt_applyRow.add(self._inlineCustomValField, BorderLayout.CENTER)
        _pt_doApplyBtn = JButton("Apply", actionPerformed=self._onInlineApplyCustomValue)
        _pt_doApplyBtn.setToolTipText("Update this key in all endpoints of the selected app and save")
        _pt_applyRow.add(_pt_doApplyBtn, BorderLayout.EAST)
        appSettingTabPanel.add(_pt_applyRow, pgbc)

        # Row 4: Profile status
        pgbc.gridy = 4; pgbc.gridx = 0; pgbc.gridwidth = 2
        pgbc.weightx = 1.0; pgbc.fill = GridBagConstraints.HORIZONTAL
        self._inlineSettingStatus = JLabel("No profile matched")
        self._inlineSettingStatus.setForeground(Color(100, 100, 100))
        appSettingTabPanel.add(self._inlineSettingStatus, pgbc)

        hashConfigContainer = JPanel(BorderLayout())
        hashConfigContainer.add(hashConfigPanel, BorderLayout.NORTH)

        cryptoConfigContainer = JPanel(BorderLayout())
        cryptoConfigContainer.add(cryptoConfigPanel, BorderLayout.NORTH)

        appSettingContainer = JPanel(BorderLayout())
        appSettingContainer.add(appSettingTabPanel, BorderLayout.NORTH)

        self._hashConfigPanel = hashConfigContainer
        self._cryptoConfigPanel = cryptoConfigContainer
        self._appSettingTabPanel = appSettingContainer

        self._configTabs = configTabs
        self._panel.add(configTabs, BorderLayout.NORTH)
        self.update_tab_visibility()

        # ================================================================
        # CENTER: CardLayout - switches between Hash/Crypto view and KF view
        # ================================================================
        from java.awt import CardLayout as _CardLayout
        self._cardLayout  = _CardLayout()
        centerPanel = JPanel(self._cardLayout)

        # ---- Card 1: Hash/Crypto - Request Body + Output ----
        hashCryptoCard = JPanel(BorderLayout(0, 4))

        bodyWrap = JPanel(BorderLayout(0, 2))
        bodyWrap.add(JLabel("Request Body:"), BorderLayout.NORTH)
        self._bodyArea = JTextPane()
        self._bodyArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._bodyArea.setEditable(editable)
        # Focus listener removed to prevent automatically rewriting float formatting (e.g. 12.00 to 12.0)
        bodyScroll = JScrollPane(self._bodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bodyWrap.add(bodyScroll, BorderLayout.CENTER)

        # Fix: give bodyWrap a minimum size so JSplitPane can never collapse it to zero
        bodyWrap.setMinimumSize(Dimension(0, 80))

        outputWrap = JPanel(BorderLayout(0, 2))
        outputWrap.setMinimumSize(Dimension(0, 40))

        # Keep the original Hash/Crypto output intact inside the first output tab.
        hashOutputPanel = JPanel(BorderLayout(0, 2))

        # Header row: label on left, checkbox on right
        outputHeader = JPanel(FlowLayout(FlowLayout.LEFT, 10, 0))
        self._autoEncryptChk = JCheckBox("Auto-encrypt on edit", True)
        self._autoEncryptChk.setToolTipText(
            "When checked: editing the decrypted text automatically re-encrypts it back into the request body"
        )
        self._autoEncryptChk.setVisible(False)  # hidden until Crypto tab is selected
        outputHeader.add(self._autoEncryptChk)
        hashOutputPanel.add(outputHeader, BorderLayout.NORTH)

        self._hashOutput = JTextArea(2, 60)
        self._hashOutput.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._hashOutput.setEditable(False)
        self._hashOutput.setLineWrap(True)
        self._hashOutput.setWrapStyleWord(True)
        outputScroll = JScrollPane(self._hashOutput)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        outputScroll.setPreferredSize(Dimension(0, 46))
        hashOutputPanel.add(outputScroll, BorderLayout.CENTER)

        # Restore the original styled Key Finder result component.
        self._inlineKfResultArea = _WrapPane()
        self._inlineKfResultArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._inlineKfResultArea.setEditable(False)
        kfOutputScroll = JScrollPane(self._inlineKfResultArea)
        kfOutputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))

        self._outputTabs = JTabbedPane(JTabbedPane.TOP)
        self._outputTabs.addTab("Hash Output", hashOutputPanel)
        self._outputTabs.addTab("Key Finder", kfOutputScroll)
        outputWrap.add(self._outputTabs, BorderLayout.CENTER)

        # ---- Debounce timer for auto-encrypt (fires 800 ms after last keystroke) ----
        self._cryptoAutoMode = False
        _outerRef = self
        class _DebounceAction(ActionListener):
            def actionPerformed(self, e):
                _outerRef._onAutoEncrypt()
        self._cryptoDebounceTimer = _SwingTimer(_DEBOUNCE_MS, _DebounceAction())
        self._cryptoDebounceTimer.setRepeats(False)

        # Document listener on Output: restart debounce when user edits plaintext
        class _OutputDocListener(DocumentListener):
            def insertUpdate(self, e):  self._trig()
            def removeUpdate(self, e):  self._trig()
            def changedUpdate(self, e): pass
            def _trig(self):
                if _outerRef._cryptoAutoMode:
                    _outerRef._cryptoDebounceTimer.restart()
        self._hashOutput.getDocument().addDocumentListener(_OutputDocListener())

        # ---- Debounce timer for auto-hash on body changes ----
        _outerRef2 = self
        class _AutoHashAction(ActionListener):
            def actionPerformed(self, e):
                try:
                    idx = _outerRef2._configTabs.getSelectedIndex()
                    if idx != 0:  # Hash tab only
                        return
                    _outerRef2._onGenerateAndInject()
                except Exception:
                    pass
        self._autoHashTimer = _SwingTimer(600, _AutoHashAction())
        self._autoHashTimer.setRepeats(False)

        class _BodyDocListener(DocumentListener):
            def insertUpdate(self, e):  self._trig()
            def removeUpdate(self, e):  self._trig()
            def changedUpdate(self, e): pass
            def _trig(self):
                if not _outerRef2._bodyLoadingProgrammatically:
                    _outerRef2._setHashStatus("")
                    _outerRef2._autoHashTimer.restart()
        self._bodyArea.getDocument().addDocumentListener(_BodyDocListener())
        self._bodyLoadingProgrammatically = False

        hcSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyWrap, outputWrap)
        hcSplit.setResizeWeight(0.92)
        hashCryptoCard.add(hcSplit, BorderLayout.CENTER)


        # ---- Card 2: AppSetting info - shows saved config for current setting ----
        settingCard = JPanel(BorderLayout(0, 6))
        settingCard.setBorder(EmptyBorder(6, 6, 6, 6))
        self._settingInfoArea = JTextArea()
        self._settingInfoArea.setEditable(False)
        self._settingInfoArea.setFont(Font("Monospaced", Font.PLAIN, _MONO_FONT_SIZE))
        self._settingInfoArea.setLineWrap(False)
        self._settingInfoArea.setText("(no app setting matched for this request)")
        settingCard.add(JScrollPane(self._settingInfoArea), BorderLayout.CENTER)

        centerPanel.add(hashCryptoCard, "hashcrypto")
        centerPanel.add(settingCard,    "setting")
        self._panel.add(centerPanel, BorderLayout.CENTER)

        # Switch cards + auto-decrypt/parse when tabs change
        _outer = self
        from javax.swing.event import ChangeListener as _CL
        class _TabListener(_CL):
            def stateChanged(self, e):
                try:
                    idx = _outer._configTabs.getSelectedIndex()
                    if idx < 0:
                        return
                    title = str(_outer._configTabs.getTitleAt(idx))
                    if title == "AppSetting":
                        _outer._autoEncryptChk.setVisible(False)
                        _outer._cryptoAutoMode = False
                        _outer._cryptoDebounceTimer.stop()
                        _outer._hashOutput.setEditable(False)
                        _outer._hashOutput.setText(_outer._lastHashText)
                        _outer._cardLayout.show(centerPanel, "setting")
                        _outer._onSettingTabFocus()
                    else:
                        _outer._cardLayout.show(centerPanel, "hashcrypto")
                        if title == "Crypto":
                            _outer._outputTabs.setTitleAt(0, "Crypto Output")
                            _outer._outputTabs.setSelectedIndex(0)
                            _outer._autoEncryptChk.setVisible(True)
                            _outer._onAutoDecrypt()
                        else:  # Hash tab
                            try:
                                mode = str(_outer._extender._activeOutputCombo.getSelectedItem())
                            except Exception:
                                mode = "Hash"
                            if mode == "Crypto":
                                _outer._outputTabs.setTitleAt(0, "Crypto Output")
                                _outer._outputTabs.setSelectedIndex(0)
                                _outer._autoEncryptChk.setVisible(True)
                                _outer._onAutoDecrypt()
                            else:
                                _outer._outputTabs.setTitleAt(0, "Hash Output")
                                _outer._autoEncryptChk.setVisible(False)
                                _outer._cryptoAutoMode = False
                                _outer._cryptoDebounceTimer.stop()
                                _outer._hashOutput.setEditable(False)
                                # Restore last hash result so crypto output doesn't bleed in
                                _outer._hashOutput.setText(_outer._lastHashText)
                except Exception:
                    pass
        configTabs.addChangeListener(_TabListener())

        # Sync config fields from the main tab if available
        self._syncFromMainTab()

    def _syncFromMainTab(self):
        """Copy config values from the main HashGen tab to this inline tab."""
        try:
            ext = self._extender
            # --- Hash tab ---
            mainAlgo = ext._algoCombo.getSelectedItem()
            if mainAlgo:
                self._algoCombo.setSelectedItem(mainAlgo)
            passcode = ext._passcodeField.getText()
            if passcode:
                self._passcodeField.setText(passcode)
            main_pairs = ext._customDataPanel.getPairs()
            if any(main_pairs.values()):
                self._customDataPanel.setPairs(main_pairs)
            mainKeys = ext._keysOrderField.getText().strip()
            if mainKeys and not self._keysUserEdited:
                self._setKeysField(mainKeys, False)
            mainHashField = ext._mainHashFieldName.getText().strip()
            if mainHashField:
                self._hashFieldName.setText(mainHashField)
            # --- Crypto tab ---
            try:
                mainCryptoAlgo = ext._cryptoAlgoCombo.getSelectedItem()
                if mainCryptoAlgo:
                    self._inlineCryptoAlgo.setSelectedItem(mainCryptoAlgo)
                # Set key/iv/field BEFORE mode so the mode-change listener fires
                # with the key already populated (avoids spurious "Key is required")
                cryptoKey = ext._cryptoKeyField.getText()
                if cryptoKey:
                    self._inlineCryptoKey.setText(cryptoKey)
                cryptoIv = ext._cryptoIvField.getText()
                if cryptoIv:
                    self._inlineCryptoIv.setText(cryptoIv)
                mainCryptoField = ext._mainCryptoField.getText().strip()
                if mainCryptoField:
                    self._inlineCryptoField.setText(mainCryptoField)
                # Do NOT sync mode — it is managed automatically by auto-decrypt/encrypt
            except Exception as e:
                print("[CipherKit] Sync crypto error: %s" % str(e))
        except Exception as e:
            print("[CipherKit] Sync error: %s" % str(e))

    def _tryLoadAppSetting(self):
        """Try to auto-load an app setting matching the current request URL path or fall back to default app setting.
        Returns True if a setting was loaded, False otherwise."""
        try:
            path = getattr(self, '_requestPath', '')
            app_name = None
            app = None
            pattern = None
            ep = None
            default_name = self._extender.ext_settings.get("default_app", "(none)")
            app_name, app, pattern, ep = (
                self._extender.app_setting_manager.resolve_for_url(path, default_name)
            )

            if not app:
                if hasattr(self, '_inlineMatchedEndpointField'):
                    self._inlineMatchedEndpointField.setText("(none)")
                if hasattr(self, '_inlineSettingStatus'):
                    self._inlineSettingStatus.setText("No profile matched")
                    self._inlineSettingStatus.setForeground(Color(100, 100, 100))
                return False

            self._applyAppSettingToInlineUI(app, ep)
            # Update AppSetting tab UI
            try:
                self._inlineSettingCombo.setSelectedItem(app_name)
                if hasattr(self, '_inlineSettingStatus'):
                    self._inlineSettingStatus.setText("Loaded: %s%s" % (app_name, (" / " + pattern) if pattern else ""))
                    self._inlineSettingStatus.setForeground(Color(0, 128, 0))
                self._inlineUrlLabel.setText(path)
                self._inlineMatchedEndpointField.setText(pattern or "(default profile)")
                if ep:
                    self._inlineEpKeysField.setText(ep.get("keys_order", ""))
                else:
                    self._inlineEpKeysField.setText("")
            except Exception:
                pass
            print("[CipherKit] Loaded app setting: %s / %s" % (app_name, pattern))
            return True
        except Exception as e:
            print("[CipherKit] AppSetting load error: %s" % str(e))
            return False

    def _applyAppSettingToInlineUI(self, app, ep=None):
        """Apply app-level setting config + optional endpoint to all inline UI fields."""
        if app.get("algorithm"):
            self._algoCombo.setSelectedItem(app["algorithm"])
        if "secret" in app:
            self._passcodeField.setText(app["secret"])
        custom_data = app.get("custom_data")
        if ep and "custom_data" in ep:
            custom_data = merge_custom_data(custom_data, ep["custom_data"])
        if custom_data:
            self._customDataPanel.setPairs(custom_data)
        else:
            kf_key = app.get("default_kf_key", "token")
            self._customDataPanel.setPairs({kf_key: ""})
        if "hash_field" in app:
            self._hashFieldName.setText(app["hash_field"])
        c = app.get("crypto", {})
        if c.get("algorithm"):
            self._inlineCryptoAlgo.setSelectedItem(c["algorithm"])
        if "key" in c:
            self._inlineCryptoKey.setText(c["key"])
        if "iv" in c:
            self._inlineCryptoIv.setText(c["iv"])
        if "field" in c:
            self._inlineCryptoField.setText(c["field"])
        # mode is managed automatically — do not set here
        if ep and "keys_order" in ep:
            self._setKeysField(ep["keys_order"], False, app=app, ep=ep)
        else:
            self._syncCustomDataForSignOrder(app=app, ep=ep)

    def _syncCustomDataForSignOrder(self, app=None, ep=None):
        """Ensure Custom Data panel displays only custom data keys required by the current Sign Order."""
        try:
            body_text = self._bodyArea.getText().strip()
            body_keys = set()
            if body_text:
                try:
                    parsed = parse_body(body_text, "")
                    body_keys = set(flatten_data(parsed).keys())
                except Exception:
                    pass

            keys_str = self._keysField.getText().strip()
            sign_keys = [k.strip() for k in keys_str.split(",") if k.strip()]
            ignore_keys = set(["hash", "signature", "sign", "sig", "mac"])
            required_custom_keys = [k for k in sign_keys if k not in body_keys and k.lower() not in ignore_keys]

            current_pairs = self._customDataPanel.getPairs()

            app_custom = app.get("custom_data", {}) if app else {}
            ep_custom = ep.get("custom_data", {}) if ep else {}
            merged_custom = merge_custom_data(app_custom, ep_custom)

            if required_custom_keys:
                new_pairs = {}
                for k in required_custom_keys:
                    if k in current_pairs and current_pairs[k].strip():
                        new_pairs[k] = current_pairs[k]
                    elif k in merged_custom and merged_custom[k]:
                        new_pairs[k] = merged_custom[k]
                    else:
                        new_pairs[k] = ""
                self._customDataPanel.setPairs(new_pairs)
            else:
                if not sign_keys and merged_custom:
                    self._customDataPanel.setPairs(merged_custom)
                elif not sign_keys:
                    kf_key = app.get("default_kf_key", "token") if app else "token"
                    self._customDataPanel.setPairs({kf_key: ""})
                else:
                    self._customDataPanel.setPairs({})
        except Exception as e:
            print("[CipherKit] Error syncing custom data for sign order: %s" % str(e))

    def _onKeysManualEdit(self):
        """Mark that the user has manually edited the keys order field."""
        if not self._keysLoadingProgrammatically:
            self._keysUserEdited = True
            self._syncCustomDataForSignOrder()

    def _setKeysField(self, value, user_edited=False, app=None, ep=None):
        """Update Sign Order without firing the manual-edit state accidentally."""
        self._keysLoadingProgrammatically = True
        try:
            self._keysField.setText(value or "")
            self._syncCustomDataForSignOrder(app=app, ep=ep)
        finally:
            self._keysLoadingProgrammatically = False
            self._keysUserEdited = bool(user_edited)

    def _updateInlinePasscodeState(self):
        """Dim/enable the Secret field based on the selected algo's requires_key flag."""
        try:
            name    = str(self._algoCombo.getSelectedItem())
            snippet = self._extender.snippet_manager.get_snippet(name)
            needs   = True
            if snippet:
                needs = snippet.get("requires_key", True)
            gray  = Color(160, 160, 160)
            black = Color(0, 0, 0)
            if needs:
                self._passcodeField.setEditable(True)
                self._passcodeField.setForeground(black)
                self._passcodeLbl.setForeground(black)
            else:
                self._passcodeField.setEditable(False)
                self._passcodeField.setForeground(gray)
                self._passcodeField.setText("")
                self._passcodeLbl.setForeground(gray)
        except Exception:
            pass

    def _setKfStatus(self, text, state="normal"):
        """Show Key Finder state only in its restored result tab."""
        self._setKfResultStyled(_safe_text(text) if text else u"")
        self._outputTabs.setSelectedIndex(1)

    def _setHashStatus(self, state):
        try:
            current_title = str(self._outputTabs.getTitleAt(0))
            if state in ("valid", "invalid", "missing"):
                self._outputTabs.setTitleAt(0, "Hash Output")
                formatted = format_hash_comparison(self._hashOutput.getText(), state)
                self._hashOutput.setText(formatted)
                self._lastHashText = formatted
            elif not current_title.startswith("Crypto Output"):
                self._outputTabs.setTitleAt(0, "Hash Output")
                plain_hash = strip_hash_comparison(self._hashOutput.getText())
                self._hashOutput.setText(plain_hash)
                self._lastHashText = plain_hash
        except Exception:
            pass

    def _tryAutoFetchFridaHook(self, auto_search=True):
        """Extract timestamp or values from body and search /tmp/cipherkit_frida.log for candidates."""
        try:
            import hashlib
            from core.key_finder import fetch_all_frida_candidates, find_key_orders
            from core.body_parser import parse_body, flatten_data

            body = self._bodyArea.getText().strip()
            if not body:
                return False

            pairs = flatten_data(parse_body(body, getattr(self, '_contentType', '')))
            ts_val = pairs.get('ts') or pairs.get('timestamp') or pairs.get('time') or pairs.get('req_time')

            candidates = fetch_all_frida_candidates(ts_val=ts_val, values=pairs)
            if not candidates:
                return False

            request_hash = ""
            for h_field in ("hash", "signature", "sign", "sig", "mac"):
                if h_field in pairs and pairs[h_field]:
                    request_hash = str(pairs[h_field]).strip().lower()
                    break

            values = dict((k, str(v)) for k, v in pairs.items())

            best_raw = None
            fallback_raw = None

            for raw_string, matched_ts, matched_via in candidates:
                matches, visited, capped = find_key_orders(values, raw_string)
                if matches:
                    if not fallback_raw:
                        fallback_raw = raw_string
                    if request_hash:
                        try:
                            raw_bytes = raw_string.encode('utf-8')
                            sha256_hex = hashlib.sha256(raw_bytes).hexdigest().lower()
                            sha1_hex = hashlib.sha1(raw_bytes).hexdigest().lower()
                            md5_hex = hashlib.md5(raw_bytes).hexdigest().lower()
                            if request_hash in (sha256_hex, sha1_hex, md5_hex):
                                best_raw = raw_string
                                break
                        except Exception:
                            pass

            selected_raw = best_raw or fallback_raw or candidates[0][0]

            if selected_raw:
                self._inlineKfKnownArea.setText(selected_raw)
                has_empty_custom = any(not str(rv).strip() for rk, rv in self._customDataPanel.getPairs().items() if rk)
                if auto_search and (not self._keysField.getText().strip() or has_empty_custom):
                    SwingUtilities.invokeLater(lambda: self._onInlineKfFind())
                return True
        except Exception as e:
            print("[CipherKit] Auto-fetch Frida error: %s" % str(e))
        return False

    def _onInlineFetchFrida(self, event=None):
        """Manual trigger to fetch Frida hook from /tmp/cipherkit_frida.log."""
        fetched = self._tryAutoFetchFridaHook(auto_search=True)
        if not fetched:
            self._setKfStatus("No Frida hook found in /tmp/cipherkit_frida.log", "error")

    def _onInlineKfFind(self, event=None):
        """Find key order on a worker thread, then apply the result on Swing."""
        try:
            from collections import OrderedDict
            from core.key_finder import find_key_orders

            known = _safe_text(self._inlineKfKnownArea.getText().strip())
            if not known:
                self._setKfStatus("Enter a known string", "error")
                return

            self._autoHashTimer.stop()
            body = self._bodyArea.getText().strip()
            pairs = OrderedDict()
            try:
                pairs.update(flatten_data(parse_body(body, "")))
            except Exception:
                pass
            for key, value in self._customDataPanel.getPairs().items():
                if key:
                    pairs[key] = value
            if not pairs:
                self._setKfStatus("No fields found", "error")
                return

            self._inlineKfFindBtn.setEnabled(False)
            self._setKfStatus("Searching...", "normal")
            values = dict((key, _safe_text(value)) for key, value in pairs.items())
            pairs_snapshot = dict(pairs)
            known_snapshot = known
            outer = self

            def run_search():
                try:
                    matches, visited, capped = find_key_orders(values, known_snapshot)

                    # --- Auto-detect gap values (token/secret) from the match result ---
                    # key_finder uses synthetic names "token"/"secret" for unknown segments.
                    # Extract the actual segment from known_snapshot and fill the UI panel.
                    auto_detect_notes = []
                    gap_values = {}
                    synthetic_gaps = []
                    if matches:
                        best_match = matches[0]
                        SYNTHETIC = ("token",)
                        # Only auto-fill if key is missing from values OR has an empty value
                        synthetic_gaps = [
                            k for k in best_match
                            if k in SYNTHETIC and (k not in values or not str(values[k]).strip())
                        ]
                        if synthetic_gaps:
                            # Reconstruct the segment positions
                            pos = 0
                            gap_values = {}  # synthetic_key -> actual_segment
                            for k in best_match:
                                val = str(values.get(k, '')).strip()
                                if val:
                                    if known_snapshot.startswith(val, pos):
                                        pos += len(val)
                                elif k in SYNTHETIC:
                                    # Find where the next real non-empty key starts
                                    found_next_idx = None
                                    for nk in best_match[list(best_match).index(k) + 1:]:
                                        nv = str(values.get(nk, '')).strip()
                                        if nv:
                                            fi = known_snapshot.find(nv, pos)
                                            if fi != -1:
                                                found_next_idx = fi
                                                break
                                    if found_next_idx is not None:
                                        gap_values[k] = known_snapshot[pos:found_next_idx]
                                        pos = found_next_idx
                                    else:
                                        gap_values[k] = known_snapshot[pos:]
                                        pos = len(known_snapshot)
                            # Fill the custom data panel rows for each synthetic gap
                            for syn_key, seg_val in gap_values.items():
                                if seg_val:
                                    auto_detect_notes.append(
                                        u"[Auto-detect] %s : %s" % (syn_key, seg_val)
                                    )
                                    # Update pairs so hash generation uses real value
                                    values[syn_key] = seg_val

                    def _apply_auto_detect_ui(gap_values_local, notes_local):
                        """Must run on Swing EDT: fill the custom data panel with detected gaps."""
                        for syn_key, seg_val in gap_values_local.items():
                            # Find an existing row with this key name, or the first empty-value row
                            filled = False
                            for row_k, row_v in outer._customDataPanel._rows:
                                rk = row_k.getText().strip()
                                rv = row_v.getText().strip()
                                if rk == syn_key:
                                    if not rv:  # only auto-fill if currently empty
                                        row_v.setText(seg_val)
                                    filled = True
                                    break
                            if not filled:
                                # Find first row with matching synthetic key name or an empty key
                                for row_k, row_v in outer._customDataPanel._rows:
                                    rk = row_k.getText().strip()
                                    rv = row_v.getText().strip()
                                    if not rk:
                                        row_k.setText(syn_key)
                                        row_v.setText(seg_val)
                                        filled = True
                                        break

                    lines = []
                    if auto_detect_notes:
                        lines.extend(auto_detect_notes + [u"\u2500" * 52])
                    if not matches:
                        lines += ["No match found.", ""]
                        found_keys = [
                            (key, value) for key, value in pairs_snapshot.items()
                            if value and _safe_text(value) in known_snapshot
                        ]
                        if found_keys:
                            lines.append("Values found in known string:")
                            lines.extend([u"  %s : %s" % (_safe_text(key), _safe_text(value))
                                          for key, value in found_keys])
                            lines.append("")
                        remaining = known_snapshot
                        for _, value in found_keys:
                            remaining = remaining.replace(_safe_text(value), u"\x00", 1)
                        unknown_parts = [part for part in remaining.split("\x00") if part]
                        if unknown_parts:
                            lines.append("Unknown segment(s) not from any field:")
                            lines.extend([u"  %s" % _safe_text(part) for part in unknown_parts])
                    else:
                        for index, match in enumerate(matches, 1):
                            if len(matches) > 1:
                                lines.append("Match #%d:" % index)
                            lines.append(u"Key order : %s" % u", ".join(
                                [_safe_text(key) for key in match]
                            ))
                            if index < len(matches):
                                lines.append("")
                    if capped:
                        lines.extend(["", "(Note: search was capped at 100 matches to optimize performance)"])
                    result_text = u"\n".join([_safe_text(line) for line in lines])

                    # Snapshot gap_values for the closure
                    gap_values_snap = dict(gap_values)
                    notes_snap = list(auto_detect_notes)

                    def finish_search():
                        outer._inlineKfFindBtn.setEnabled(True)
                        outer._lastKfMatches = matches
                        state = "found" if matches else "error"
                        outer._setKfStatus(result_text, state)
                        if gap_values_snap:
                            _apply_auto_detect_ui(gap_values_snap, notes_snap)
                        if matches:
                            outer._onInlineApplyResult("", capped)

                    SwingUtilities.invokeLater(finish_search)
                except Exception as error:
                    error_text = "Error: %s\n%s" % (str(error), traceback.format_exc())

                    def finish_error():
                        outer._lastKfMatches = []
                        outer._inlineKfFindBtn.setEnabled(True)
                        outer._setKfStatus(error_text, "error")

                    SwingUtilities.invokeLater(finish_error)

            import threading
            worker = threading.Thread(target=run_search)
            worker.setDaemon(True)
            worker.start()
        except Exception as error:
            self._lastKfMatches = []
            self._inlineKfFindBtn.setEnabled(True)
            self._setKfStatus("Error: %s\n%s" % (str(error), traceback.format_exc()), "error")
            print("[CipherKit] Key Finder error: %s\n%s" % (str(error), traceback.format_exc()))

    def _setKfResultStyled(self, text):
        """Restore the legacy styled Key Finder result rendering."""
        from javax.swing.text import SimpleAttributeSet, StyleConstants
        doc = self._inlineKfResultArea.getStyledDocument()
        doc.remove(0, doc.getLength())
        normal = SimpleAttributeSet()
        StyleConstants.setFontFamily(normal, "Monospaced")
        StyleConstants.setFontSize(normal, _MONO_FONT_SIZE)
        StyleConstants.setForeground(normal, Color(30, 30, 30))
        highlight = SimpleAttributeSet()
        StyleConstants.setFontFamily(highlight, "Monospaced")
        StyleConstants.setFontSize(highlight, _MONO_FONT_SIZE)
        StyleConstants.setForeground(highlight, Color(0, 85, 170))
        for line in _safe_text(text).splitlines():
            if line.startswith("Key order :"):
                display = line[len("Key order :"):].strip()
                doc.insertString(doc.getLength(), display + "\n", highlight)
            else:
                doc.insertString(doc.getLength(), line + "\n", normal)

    def _onInlineApplyResult(self, note="", capped=False, event=None):
        """Apply the chosen Key Finder result to the Hash tab's fields."""
        if not self._lastKfMatches:
            self._setKfStatus("No match", "error")
            return

        selected_match = None
        
        # Check if the endpoint already exists in the app settings and has a keys order
        path = getattr(self, '_requestPath', '')
        if path:
            try:
                app_name, app, pattern, ep = self._extender.app_setting_manager.find_by_url(path)
                if ep and ep.get("keys_order"):
                    existing_order = ep.get("keys_order", "").strip()
                    if existing_order:
                        existing_keys = tuple(k.strip() for k in existing_order.split(",") if k.strip())
                        # Check if any match matches the existing keys order
                        for m in self._lastKfMatches:
                            if tuple(m) == existing_keys:
                                selected_match = m
                                break
            except Exception:
                pass

        if not selected_match:
            if len(self._lastKfMatches) == 1:
                selected_match = self._lastKfMatches[0]
            else:
                options = [u", ".join([_safe_text(key) for key in match])
                           for match in self._lastKfMatches]
                selected = JOptionPane.showInputDialog(
                    self._panel,
                    "Multiple matches found. Select which key order to apply:",
                    "Select Key Order",
                    JOptionPane.QUESTION_MESSAGE,
                    None,
                    options,
                    options[0]
                )
                if selected:
                    try:
                        idx = options.index(selected)
                        selected_match = self._lastKfMatches[idx]
                    except ValueError:
                        pass

        if selected_match:
            # 1. Update Sign Order field
            self._setKeysField(
                u", ".join([_safe_text(key) for key in selected_match]), True
            )

            # 2. No merge needed — Custom Data panel is shared with Key Finder
            #    _customDataPanel already contains all extra fields (token, etc.)

            # 3. Switch view/focus to the Hash tab (index 0)
            self._configTabs.setSelectedIndex(0)

            # 4. Trigger one hash generation and compare it with the request hash.
            try:
                self._outputTabs.setSelectedIndex(0)
                self._shouldCompareHash = True
                self._onGenerate()
            except Exception:
                pass
        else:
            # Keep the full match list visible when selection is cancelled.
            self._outputTabs.setSelectedIndex(1)

    def update_tab_visibility(self):
        show_crypto = self._extender.ext_settings.get("show_crypto", False)
        show_as = self._extender.ext_settings.get("show_app_setting", True)
        show_ts = self._extender.ext_settings.get("show_get_timestamp", False)
        show_run_hash = self._extender.ext_settings.get("show_run_hash", True)

        self._configTabs.removeAll()
        self._configTabs.addTab("Hash", self._hashConfigPanel)
        if show_crypto:
            self._configTabs.addTab("Crypto", self._cryptoConfigPanel)
        if show_as:
            self._configTabs.addTab("AppSetting", self._appSettingTabPanel)

        if hasattr(self, '_runHashBtn') and self._runHashBtn:
            self._runHashBtn.setVisible(show_run_hash)
        if hasattr(self, '_inlineTsBtn') and self._inlineTsBtn:
            self._inlineTsBtn.setVisible(show_ts)
        if hasattr(self, '_hashBtnPanel') and self._hashBtnPanel:
            self._hashBtnPanel.setVisible(show_run_hash or show_ts)

    def _onManualRunHash(self, event=None):
        """Manually compute hash and print to output (without modifying/injecting request body)."""
        self._shouldCompareHash = True
        self._onGenerate()




    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._panel

    def _resetEditorState(self, content=None):
        self._currentMessage = content
        self._contentType = ""
        self._requestPath = ""
        self._bodyLoadingProgrammatically = True
        self._bodyArea.setText("")
        self._bodyLoadingProgrammatically = False
        self._hashOutput.setEditable(False)
        self._hashOutput.setText("")
        self._setHashStatus("")
        self._inlineKfResultArea.setText("")
        self._outputTabs.setTitleAt(0, "Hash Output")
        self._outputTabs.setSelectedIndex(0)
        self._cryptoAutoMode = False
        try:
            self._cryptoDebounceTimer.stop()
        except Exception:
            pass

    def isEnabled(self, content, isRequest):
        if not isRequest or content is None:
            return False
        try:
            analyzed = self._helpers.analyzeRequest(content)
            bodyOffset = analyzed.getBodyOffset()
            body = self._helpers.bytesToString(content[bodyOffset:])
            return len(body.strip()) > 0
        except:
            return False

    def setMessage(self, content, isRequest):
        self._isRequestContext = bool(isRequest)
        if content is None or not isRequest:
            self._resetEditorState(content)
            return

        try:
            self._currentMessage = content
            analyzed = self._helpers.analyzeRequest(content)
            bodyOffset = analyzed.getBodyOffset()

            # Extract Content-Type from headers for body parsing
            self._contentType = ""
            for h in analyzed.getHeaders():
                if h.lower().startswith("content-type:"):
                    self._contentType = h[len("content-type:"):].strip()
                    break

            body = self._helpers.bytesToString(content[bodyOffset:])

            self._bodyLoadingProgrammatically = True
            self._bodyArea.setText(body)
            self._tryFormatJson()
            self._bodyArea.setCaretPosition(0)
            self._bodyLoadingProgrammatically = False

            # Extract URL path for app setting matching
            new_request_path = _extract_request_path(analyzed)
            path_changed = (new_request_path != getattr(self, '_requestPath', ''))
            self._requestPath = new_request_path

            # Only reset Sign Order and Custom Data if switching to a DIFFERENT URL path
            if path_changed:
                self._setKeysField("", False)
                self._customDataPanel.setPairs({})

            # Try auto-load an app setting matching this URL path
            setting_loaded = self._tryLoadAppSetting()

            # Only auto-extract keys if no setting was loaded and Sign Order is empty
            if not setting_loaded and not self._keysUserEdited and not self._keysField.getText().strip():
                self._tryExtractKeys()

            # Sync remaining config from main tab (only fields not set by app setting)
            if not setting_loaded:
                self._syncFromMainTab()

            # Auto-fetch Frida hook matching request timestamp/parameters if available
            if path_changed or not self._keysField.getText().strip():
                self._tryAutoFetchFridaHook(auto_search=True)

            # If the Crypto tab is already selected, re-run auto-decrypt now that
            # key/iv have been populated (the mode-change listener may have fired
            # before the key was set, producing a spurious "Key is required" error)
            try:
                idx = self._configTabs.getSelectedIndex()
                title = str(self._configTabs.getTitleAt(idx)) if idx >= 0 else ""
                if title == "Crypto":
                    self._onAutoDecrypt()
                elif title == "Hash":
                    self._onGenerate()
                else:
                    self._onSettingTabFocus()
            except Exception:
                pass
        except Exception as e:
            self._resetEditorState(content)
            print("[CipherKit] Inline tab setMessage error: %s" % str(e))
            print(traceback.format_exc())
            return

    def getMessage(self):
        if self._currentMessage is None or not self._isRequestContext:
            return self._currentMessage

        try:
            body_str = self._bodyArea.getText()
            body_bytes = self._helpers.stringToBytes(body_str)

            analyzed = self._helpers.analyzeRequest(self._currentMessage)
            headers = analyzed.getHeaders()
            return self._helpers.buildHttpMessage(headers, body_bytes)
        except Exception as e:
            print("[CipherKit] Inline tab getMessage error: %s" % str(e))
            print(traceback.format_exc())
            return self._currentMessage

    def isModified(self):
        if self._currentMessage is None or not self._isRequestContext:
            return False
        try:
            analyzed = self._helpers.analyzeRequest(self._currentMessage)
            bodyOffset = analyzed.getBodyOffset()
            originalBody = self._helpers.bytesToString(self._currentMessage[bodyOffset:]).strip()
            currentBody = self._bodyArea.getText().strip()
            return originalBody != currentBody
        except Exception as e:
            print("[CipherKit] Inline tab isModified error: %s" % str(e))
            print(traceback.format_exc())
            return False

    def getSelectedData(self):
        selected = self._bodyArea.getSelectedText()
        if selected:
            return self._helpers.stringToBytes(selected)
        return None

    # --- Actions ---

    def _onGenerate(self, event=None):
        compare_requested = bool(getattr(self, '_shouldCompareHash', True))
        result, debug_log = self._computeHash()
        try:
            crypto_output_mode = str(self._extender._activeOutputCombo.getSelectedItem()) == "Crypto"
        except Exception:
            crypto_output_mode = False
        if should_render_hash_output(compare_requested, crypto_output_mode):
            text = str(result)
            self._lastHashText = text
            self._hashOutput.setText(text)
        try:
            body_str = self._bodyArea.getText().strip()
            payload = parse_body(body_str, getattr(self, '_contentType', ''))
            comparable_payload = flatten_data(payload) if isinstance(payload, dict) else payload
            hash_field = self._hashFieldName.getText().strip() or "hash"
            self._setHashStatus(compare_generated_hash(result, comparable_payload, hash_field))
        finally:
            self._shouldCompareHash = False

    def _onGenerateAndInject(self, event=None):
        result, debug_log = self._computeHash()
        # Determine if Hash tab output is in Crypto mode (output area shows decrypted text)
        try:
            crypto_output_mode = str(self._extender._activeOutputCombo.getSelectedItem()) == "Crypto"
        except Exception:
            crypto_output_mode = False
        if result and not str(result).startswith("Error"):
            body_str = self._bodyArea.getText().strip()
            try:
                ct = getattr(self, '_contentType', '')
                data = parse_body(body_str, ct)
                field_name = self._hashFieldName.getText().strip() or "hash"
                if isinstance(data, dict):
                    data[field_name] = str(result)
                    serialized = serialize_body(data, body_str, ct)
                    old_prog = self._bodyLoadingProgrammatically
                    self._bodyLoadingProgrammatically = True
                    try:
                        old_caret = self._bodyArea.getCaretPosition()
                        self._bodyArea.setText(serialized)
                        self._tryFormatJson()
                        new_len = len(self._bodyArea.getText())
                        self._bodyArea.setCaretPosition(min(old_caret, new_len))
                    finally:
                        self._bodyLoadingProgrammatically = old_prog
                # Only update the output area when NOT in Crypto mode
                if not crypto_output_mode:
                    text = str(result)
                    self._lastHashText = text
                    self._hashOutput.setText(text)
                
                # Check comparison match status
                comparable_payload = flatten_data(data) if isinstance(data, dict) else parse_body(body_str, ct)
                self._setHashStatus(compare_generated_hash(result, comparable_payload, field_name))
            except Exception as e:
                self._hashOutput.setText("Error injecting hash: %s" % str(e))
        else:
            if not crypto_output_mode:
                self._lastHashText = str(result)
                self._hashOutput.setText(str(result))

    def _onInlineSaveSetting(self, event=None):
        """Save current config as an app setting + endpoint.
        Reads the app name from the combo and keys order from the AppSetting tab field."""
        path = getattr(self, '_requestPath', '')

        # App name: use combo selection or ask
        selected_combo = str(self._inlineSettingCombo.getSelectedItem())
        existing = self._extender.app_setting_manager.get_all_names()

        if selected_combo and selected_combo != "(none)":
            app_name = selected_combo
        else:
            choices = existing + ["[ New app... ]"]
            app_name = JOptionPane.showInputDialog(
                self._panel, "App setting name (select existing or type new):", "Save Endpoint",
                JOptionPane.PLAIN_MESSAGE, None,
                choices if choices else None,
                existing[0] if existing else ""
            )
            if not app_name or not str(app_name).strip():
                return
            app_name = str(app_name).strip()

        if app_name == "[ New app... ]":
            app_name = JOptionPane.showInputDialog(
                self._panel, "New app name:", "Save Endpoint",
                JOptionPane.PLAIN_MESSAGE, None, None, ""
            )
            if not app_name or not str(app_name).strip():
                return
            app_name = str(app_name).strip()

        # URL pattern: pre-fill from AppSetting tab URL label or current path
        pattern = JOptionPane.showInputDialog(
            self._panel, "URL pattern for this endpoint (e.g. /api/user):",
            "URL Pattern", JOptionPane.PLAIN_MESSAGE, None, None, path
        )
        pattern = str(pattern).strip() if pattern else ""

        # Keys order: prefer AppSetting tab field (user may have edited it there)
        try:
            keys_order = self._inlineEpKeysField.getText().strip() or self._keysField.getText().strip()
        except Exception:
            keys_order = self._keysField.getText().strip()

        # Determine which custom data panel to read from based on the active tab
        idx = self._configTabs.getSelectedIndex()
        active_title = str(self._configTabs.getTitleAt(idx)) if idx >= 0 else ""
        # Always use the unified Custom Data panel (Key Finder and Hash tab share the same panel)
        resolved_custom_data = self._customDataPanel.getPairs()

        # Save app-level config (algorithm, secret, crypto - shared across endpoints)
        app_data = {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": resolved_custom_data,
            "hash_field":  self._hashFieldName.getText().strip() or "hash",
            "crypto": {
                "mode":      str(self._inlineCryptoMode.getSelectedItem()),
                "algorithm": str(self._inlineCryptoAlgo.getSelectedItem()),
                "key":       self._inlineCryptoKey.getText(),
                "iv":        self._inlineCryptoIv.getText(),
                "field":     self._inlineCryptoField.getText().strip() or "data",
            },
        }
        self._extender.app_setting_manager.save_app(app_name, app_data)
        if pattern:
            self._extender.app_setting_manager.save_endpoint(app_name, pattern, keys_order, resolved_custom_data)

        self._refreshInlineSettingCombo()
        self._inlineSettingCombo.setSelectedItem(app_name)
        try:
            self._extender._refreshSettingCombo()
        except:
            pass
        label = "%s%s" % (app_name, (" / " + pattern) if pattern else "")
        try:
            if hasattr(self, '_inlineSettingStatus'):
                self._inlineSettingStatus.setText("Saved: %s" % label)
                self._inlineSettingStatus.setForeground(Color(0, 128, 0))
            if pattern and hasattr(self, '_inlineMatchedEndpointField'):
                self._inlineMatchedEndpointField.setText(pattern)
        except Exception:
            pass
        self._hashOutput.setText("Saved: %s" % label)
        print("[CipherKit] AppSetting saved: %s" % label)

    def _onInlineLoadSetting(self, event=None):
        """Manually load the selected app setting into all config fields."""
        name = str(self._inlineSettingCombo.getSelectedItem())
        if name == "(none)":
            return
        app = self._extender.app_setting_manager.get_app(name)
        if not app:
            return
        try:
            path = getattr(self, '_requestPath', '')
            matched_pattern, matched_ep = (
                self._extender.app_setting_manager.find_endpoint_in_app(name, path)
            )
            self._applyAppSettingToInlineUI(app, matched_ep)
            self._inlineMatchedEndpointField.setText(matched_pattern or "(none)")
            if matched_ep:
                self._inlineEpKeysField.setText(matched_ep.get("keys_order", ""))
                self._inlineSettingStatus.setText(
                    "Loaded: %s / %s" % (name, matched_pattern)
                )
                self._inlineSettingStatus.setForeground(Color(0, 128, 0))
            else:
                self._inlineEpKeysField.setText("")
                self._inlineSettingStatus.setText(
                    "Loaded profile; current URL has no saved endpoint"
                )
                self._inlineSettingStatus.setForeground(Color(170, 110, 0))
            self._refreshInlineSettingInfo()
            print("[CipherKit] Manually loaded setting: %s / %s" % (
                name, matched_pattern or "(none)"
            ))
        except Exception as e:
            print("[CipherKit] Load setting error: %s" % str(e))

    def _onOpenMainAppSetting(self, event=None):
        """Prepare the full AppSetting suite tab for profile management."""
        try:
            selected_name = str(self._inlineSettingCombo.getSelectedItem())
            self._extender.show_main_app_setting(selected_name)
            self._inlineSettingStatus.setText(
                "Main AppSetting selected; open the CipherKit suite tab"
            )
            self._inlineSettingStatus.setForeground(Color(80, 80, 80))
        except Exception as e:
            self._inlineSettingStatus.setText("Could not open main AppSetting")
            self._inlineSettingStatus.setForeground(Color(180, 0, 0))
            print("[CipherKit] Open main AppSetting error: %s" % str(e))

    @staticmethod
    def _refill_setting_combo(combo, names):
        """Repopulate an AppSetting JComboBox, restoring prior selection if still present."""
        current = str(combo.getSelectedItem())
        combo.removeAllItems()
        combo.addItem("(none)")
        for n in names:
            combo.addItem(n)
        if current and current != "(none)":
            combo.setSelectedItem(current)

    def _refreshInlineSettingCombo(self):
        """Refresh the inline setting combo box with current app names."""
        try:
            self._refill_setting_combo(
                self._inlineSettingCombo,
                self._extender.app_setting_manager.get_all_names()
            )
        except Exception as e:
            print("[CipherKit] Refresh inline combo error: %s" % str(e))

    def _onSettingTabFocus(self):
        """Populate the AppSetting tab fields and info area when switching to it."""
        try:
            path = getattr(self, '_requestPath', '')
            self._inlineUrlLabel.setText(path or "(no request loaded)")
            self._inlineEpKeysField.setText(self._keysField.getText())
            name = str(self._inlineSettingCombo.getSelectedItem())
            pattern, endpoint = (
                self._extender.app_setting_manager.find_endpoint_in_app(name, path)
                if name and name != "(none)" else (None, None)
            )
            self._inlineMatchedEndpointField.setText(pattern or "(none)")
            if endpoint and endpoint.get("keys_order"):
                self._inlineEpKeysField.setText(endpoint.get("keys_order", ""))
            self._refreshInlineSettingInfo()
        except Exception as e:
            print("[CipherKit] AppSetting tab focus error: %s" % str(e))

    def _refreshInlineSettingInfo(self):
        """Show a compact, redacted summary for the current request/profile."""
        try:
            name = str(self._inlineSettingCombo.getSelectedItem())
            if name == "(none)":
                self._settingInfoArea.setText("(no setting selected - pick one from the dropdown above)")
                self._inlineMatchedEndpointField.setText("(none)")
                self._inlineSettingStatus.setText("No profile selected")
                self._inlineSettingStatus.setForeground(Color(100, 100, 100))
                return
            app = self._extender.app_setting_manager.get_app(name)
            if not app:
                self._settingInfoArea.setText("(setting '%s' not found)" % name)
                return
            path = getattr(self, '_requestPath', '')
            pattern, endpoint = (
                self._extender.app_setting_manager.find_endpoint_in_app(name, path)
            )
            self._inlineMatchedEndpointField.setText(pattern or "(none)")
            if pattern:
                self._inlineSettingStatus.setText("Profile matched: %s" % pattern)
                self._inlineSettingStatus.setForeground(Color(0, 128, 0))
            else:
                self._inlineSettingStatus.setText(
                    "Profile selected; current URL has no saved endpoint"
                )
                self._inlineSettingStatus.setForeground(Color(170, 110, 0))
            lines = []
            lines.append("App Setting : %s" % name)
            lines.append("Current URL: %s" % (path or "(none)"))
            lines.append("Matched Endpoint: %s" % (pattern or "(none)"))
            lines.append("")
            lines.append("Request Profile")
            lines.append("-" * 40)
            lines.append("  Algorithm : %s" % app.get("algorithm", ""))
            lines.append("  Hash Field: %s" % app.get("hash_field", ""))
            if app.get("secret"):
                lines.append("  Secret    : %s" % mask_secret(app.get("secret")))
            custom_data = app.get("custom_data", {})
            if custom_data:
                lines.append("  Shared Custom Keys: %s" % ", ".join(custom_data.keys()))
            if endpoint:
                lines.append("  Sign Order: %s" % endpoint.get("keys_order", ""))
                endpoint_custom = endpoint.get("custom_data", {})
                if endpoint_custom:
                    lines.append("  Endpoint Custom Keys: %s" % ", ".join(endpoint_custom.keys()))
            else:
                lines.append("")
                lines.append("No endpoint matches this request.")
                lines.append("Set Sign Order above, then click Save Endpoint.")

            endpoints = app.get("endpoints", {})
            if endpoints:
                lines.append("")
                lines.append("Saved Endpoints (Alphabetical Order)")
                lines.append("=" * 60)
                lines.append("   %-25s | %s" % ("Endpoint URL Path", "Sign Order"))
                lines.append("   " + "-" * 25 + "-+-" + "-" * 28)
                for pat, ep in sorted(endpoints.items(), key=lambda x: str(x[0]).lower()):
                    prefix = "-> " if pat == pattern else "   "
                    lines.append("%s%-25s | %s" % (prefix, pat, ep.get("keys_order", "")))

            self._settingInfoArea.setText("\n".join(lines))
            self._settingInfoArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] Setting info refresh error: %s" % str(e))

    def _onInlineDeleteSetting(self, event=None):
        """Delete the selected app setting."""
        name = str(self._inlineSettingCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._panel, "Delete app setting '%s' and all its endpoints?" % name,
            "Delete Setting", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self._extender.app_setting_manager.delete_app(name)
            self._refreshInlineSettingCombo()
            try:
                self._extender._refreshSettingCombo()
            except:
                pass
            if hasattr(self, '_inlineSettingStatus'):
                self._inlineSettingStatus.setText("Deleted: %s" % name)
            print("[CipherKit] AppSetting deleted: %s" % name)

    def _onInlineApplyCustomValue(self, event=None):
        """Read key name + value from the inline fields and bulk-update across all
        endpoints (and shared custom_data) of the currently selected app."""
        name = str(self._inlineSettingCombo.getSelectedItem())
        if name == "(none)":
            JOptionPane.showMessageDialog(self._panel, "Please select an app setting first.",
                                          "Apply Custom Value", JOptionPane.WARNING_MESSAGE)
            return
        mgr = self._extender.app_setting_manager
        app = mgr.get_app(name)
        if not app:
            JOptionPane.showMessageDialog(self._panel, "App configuration not found.",
                                          "Apply Custom Value", JOptionPane.ERROR_MESSAGE)
            return

        key_name = self._inlineCustomKeyField.getText().strip()
        if not key_name:
            JOptionPane.showMessageDialog(self._panel, "Please enter a key name.",
                                          "Apply Custom Value", JOptionPane.WARNING_MESSAGE)
            return
        new_val = self._inlineCustomValField.getText()  # allow empty string

        # Update wherever the key appears in settings
        count = 0
        shared = app.get("custom_data", {})
        if key_name in shared:
            shared[key_name] = new_val
            count += 1
        for pat, ep in app.get("endpoints", {}).items():
            ep_custom = ep.get("custom_data", {})
            if key_name in ep_custom:
                ep_custom[key_name] = new_val
                count += 1

        if count == 0:
            JOptionPane.showMessageDialog(
                self._panel,
                "Key '%s' was not found in any custom data for app '%s'.\n"
                "Check that the key exists in at least one endpoint's Custom Data." % (key_name, name),
                "Apply Custom Value", JOptionPane.WARNING_MESSAGE)
            return

        mgr.save()

        # Update current active UI's custom data panel if the key is loaded
        try:
            hash_pairs = self._customDataPanel.getPairs()
            if key_name in hash_pairs:
                hash_pairs[key_name] = new_val
                self._customDataPanel.setPairs(hash_pairs)
                # Auto-generate the hash to update output immediately!
                self._onGenerate()
        except Exception as e:
            print("[CipherKit] Error updating current UI Custom Data: %s" % str(e))

        # Also refresh main tab summary and inline tab summary if available
        try:
            self._extender._refreshSettingSummary()
        except Exception:
            pass
        try:
            self._refreshInlineSettingInfo()
        except Exception:
            pass

    def _onCryptoRun(self, event=None):
        """Run AES-CBC encrypt/decrypt on the named body field and show result."""
        try:
            self._outputTabs.setTitleAt(0, "Crypto Output")
            self._outputTabs.setSelectedIndex(0)
            result = self._computeCrypto()
            self._hashOutput.setText("[CRYPTO] " + str(result))
        except Exception as e:
            self._hashOutput.setText("[CRYPTO] Error: %s" % str(e))

    def _onAutoDecrypt(self):
        """Auto-decrypt the named field when switching to Crypto tab (Decrypt mode only).
        Silently clears the output and does nothing when required params are missing."""
        self._cryptoAutoMode = False
        self._cryptoDebounceTimer.stop()
        self._outputTabs.setTitleAt(0, "Crypto Output")
        self._outputTabs.setSelectedIndex(0)
        # Always force Decrypt — mode is managed automatically, never set externally
        self._inlineCryptoMode.setSelectedItem("Decrypt")
        # Silently skip if required parameters are not yet filled in
        key   = self._inlineCryptoKey.getText().strip()
        field = self._inlineCryptoField.getText().strip()
        if not key or not field:
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            return
        try:
            result = self._computeCrypto()
            if result and not str(result).startswith("Error"):
                self._hashOutput.setEditable(True)
                self._hashOutput.setText(str(result))
                self._cryptoAutoMode = True
                self._lastEncryptedPlaintext = None  # fresh decrypt — allow next edit to encrypt
            else:
                self._hashOutput.setEditable(False)
                self._hashOutput.setText("")
        except Exception as e:
            self._hashOutput.setEditable(False)
            self._hashOutput.setText("")
            print("[CipherKit] Auto-decrypt error: %s" % str(e))

    def _onAutoEncrypt(self):
        """Debounced: encrypt the plaintext in Output and inject back into the body field."""
        if not self._cryptoAutoMode:
            return
        # Check local auto-encrypt checkbox (Crypto tab only; Hash tab inherits the state)
        if not self._autoEncryptChk.isSelected():
            return
        # Check global session checkbox in main tab
        try:
            if not self._extender._globalAutoEncryptChk.isSelected():
                return
        except Exception:
            pass
        # Silently skip if required parameters are missing
        key = self._inlineCryptoKey.getText().strip()
        if not key:
            return
        try:
            plaintext = self._hashOutput.getText()
            if not plaintext:
                return
            # Skip if plaintext hasn't changed since the last encrypt (prevents loops)
            if plaintext == getattr(self, '_lastEncryptedPlaintext', None):
                return
            iv    = self._inlineCryptoIv.getText().strip() or None
            field = self._inlineCryptoField.getText().strip() or "data"
            algo    = str(self._inlineCryptoAlgo.getSelectedItem()) if hasattr(self, '_inlineCryptoAlgo') else "AES-CBC-128"
            snippet = self._extender.crypto_snippet_manager.get_snippet(algo)
            if snippet:
                encrypted = CryptoSnippetEngine.execute(snippet, "Encrypt", plaintext, key, iv or "")
            else:
                encrypted = AesCbcEngine.encrypt(plaintext, key, iv)
            body_str   = self._bodyArea.getText().strip()
            ct         = getattr(self, '_contentType', '')
            data       = parse_body(body_str, ct)
            data[field] = str(encrypted)
            serialized  = serialize_body(data, body_str, ct)
            self._lastEncryptedPlaintext = plaintext  # guard against re-encrypt loop
            old_caret = self._bodyArea.getCaretPosition()
            self._bodyArea.setText(serialized)
            self._tryFormatJson()
            new_len = len(self._bodyArea.getText())
            self._bodyArea.setCaretPosition(min(old_caret, new_len))
        except Exception as e:
            print("[CipherKit] Auto-encrypt error: %s" % str(e))

    def _computeCrypto(self):
        """Read crypto config, read field value from body, run selected algorithm."""
        mode  = str(self._inlineCryptoMode.getSelectedItem())
        key   = self._inlineCryptoKey.getText()
        iv    = self._inlineCryptoIv.getText().strip() or ""
        field = self._inlineCryptoField.getText().strip() or "data"
        algo  = str(self._inlineCryptoAlgo.getSelectedItem()) if hasattr(self, '_inlineCryptoAlgo') else "AES-CBC-128"

        if not key:
            return "Error: Crypto Key is required."

        body_str = self._bodyArea.getText().strip()
        ct       = getattr(self, '_contentType', '')
        data     = parse_body(body_str, ct)

        field_value = ""
        if isinstance(data, dict) and field in data:
            field_value = str(data[field])
        elif body_str:
            field_value = body_str

        if not field_value:
            return "Error: Field '%s' not found or empty in body." % field

        # Dispatch through snippet system; fall back to built-in AesCbcEngine
        snippet = self._extender.crypto_snippet_manager.get_snippet(algo)
        if snippet:
            return CryptoSnippetEngine.execute(snippet, mode, field_value, key, iv)
        else:
            if mode == "Encrypt":
                return AesCbcEngine.encrypt(field_value, key, iv or None)
            else:
                return AesCbcEngine.decrypt(field_value, key, iv or None)

    def _computeHash(self):
        name = self._algoCombo.getSelectedItem()
        if not name:
            return "Error: No algorithm selected.", ""

        snippet = self._extender.snippet_manager.get_snippet(str(name))
        if not snippet:
            return "Error: Snippet '%s' not found." % name, ""

        try:
            body_str = self._bodyArea.getText().strip()
            ct = getattr(self, '_contentType', '')
            payload = parse_body(body_str, ct)
            if not payload:
                return "Error: Body could not be parsed or is empty.", ""
            passcode = self._passcodeField.getText()
            custom_data = self._customDataPanel.getPairs()

            keys_str = self._keysField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            result, debug_log = CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, custom_data, key_order
            )

            result_str = str(result)
            if not result_str.startswith("Error") and self._extender._globalUppercaseHashChk.isSelected():
                result_str = result_str.upper()

            return result_str, debug_log
        except Exception as e:
            return "Error: %s" % str(e), traceback.format_exc()

    def _tryExtractKeys(self):
        """Auto-extract keys from body (any format). Only if user hasn't manually edited."""
        try:
            body_str = self._bodyArea.getText().strip()
            if not body_str:
                return
            ct = getattr(self, '_contentType', '')
            data = parse_body(body_str, ct)
            if isinstance(data, dict) and data:
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysField.getText().strip()
                if current != new_keys_str:
                    self._setKeysField(new_keys_str, False)
        except:
            pass

    def _tryFormatJson(self):
        """Pretty-print body preserving float formatting and exact token values, with syntax coloring."""
        try:
            body_str = self._bodyArea.getText()
            if not body_str:
                return
            body_str = body_str.strip()
            if not body_str:
                return
            
            # Simple check if it looks like a JSON object or array
            if not (body_str.startswith('{') or body_str.startswith('[')):
                return
            
            # Validate using standard json.loads first to make sure it's valid JSON
            try:
                json.loads(body_str)
            except:
                return
                
            import re
            from javax.swing.text import SimpleAttributeSet, StyleConstants
            
            # Match strings, numbers, booleans, null, structural chars, or whitespace
            token_pattern = re.compile(
                r'"(?:\\.|[^"\\])*"'            # Double-quoted strings (handling escapes)
                r"|[-+]?\d*\.\d+(?:[eE][-+]?\d+)?" # Floating-point numbers
                r"|[-+]?\d+"                     # Integers
                r"|true|false|null"              # Booleans and Null
                r"|[{}[\]:,]"                    # Structural characters
                r"|\s+"                          # Whitespace
            )
            
            tokens = token_pattern.findall(body_str)
            # Filter out whitespace tokens
            non_ws_tokens = [t for t in tokens if not t.isspace()]
            
            if not non_ws_tokens:
                return

            # Determine colors based on active theme background
            bg = self._bodyArea.getBackground()
            luminance = 0.2126 * bg.getRed() + 0.7152 * bg.getGreen() + 0.0722 * bg.getBlue()
            is_dark = luminance < 128
            
            if is_dark:
                color_struct = Color(204, 204, 204)
                color_key = Color(156, 220, 254)
                color_val = Color(206, 145, 120)
                color_num = Color(181, 206, 168)
                color_bool = Color(86, 156, 214)
            else:
                color_struct = Color(50, 50, 50)
                color_key = Color(0, 0, 128)
                color_val = Color(0, 128, 0)
                color_num = Color(9, 134, 115)
                color_bool = Color(0, 0, 255)

            def get_attr(color):
                attr = SimpleAttributeSet()
                StyleConstants.setForeground(attr, color)
                StyleConstants.setFontFamily(attr, "Monospaced")
                StyleConstants.setFontSize(attr, 12)
                return attr

            attr_struct = get_attr(color_struct)
            attr_key = get_attr(color_key)
            attr_val = get_attr(color_val)
            attr_num = get_attr(color_num)
            attr_bool = get_attr(color_bool)
                
            out = []
            indent_level = 0
            indent_size = 2
            i = 0
            n = len(non_ws_tokens)
            state_stack = []
            expecting_key = False
            
            while i < n:
                tok = non_ws_tokens[i]
                
                if tok in ('{', '['):
                    if tok == '{':
                        state_stack.append('object')
                        expecting_key = True
                    else:
                        state_stack.append('array')
                        expecting_key = False
                    
                    out.append((tok, attr_struct))
                    
                    # Check if next token is closing
                    if i + 1 < n and non_ws_tokens[i + 1] == ('}' if tok == '{' else ']'):
                        closing_tok = non_ws_tokens[i + 1]
                        out.append((closing_tok, attr_struct))
                        state_stack.pop()
                        i += 2
                        continue
                    
                    indent_level += 1
                    out.append(('\n' + (' ' * (indent_level * indent_size)), attr_struct))
                    
                elif tok in ('}', ']'):
                    if state_stack:
                        state_stack.pop()
                    indent_level = max(0, indent_level - 1)
                    out.append(('\n' + (' ' * (indent_level * indent_size)), attr_struct))
                    out.append((tok, attr_struct))
                    
                elif tok == ',':
                    if state_stack and state_stack[-1] == 'object':
                        expecting_key = True
                    out.append((tok, attr_struct))
                    out.append(('\n' + (' ' * (indent_level * indent_size)), attr_struct))
                    
                elif tok == ':':
                    expecting_key = False
                    out.append((': ', attr_struct))
                    
                else:
                    # Value token
                    attr = attr_struct
                    if tok.startswith('"'):
                        if state_stack and state_stack[-1] == 'object' and expecting_key:
                            attr = attr_key
                        else:
                            attr = attr_val
                    elif tok in ('true', 'false', 'null'):
                        attr = attr_bool
                    else:
                        attr = attr_num
                    out.append((tok, attr))
                    
                i += 1
                
            # Populate JTextPane document with styled content
            doc = self._bodyArea.getStyledDocument()
            doc.remove(0, doc.getLength())
            for text, attr in out:
                doc.insertString(doc.getLength(), text, attr)
        except Exception as e:
            print("[CipherKit] Error pretty-printing JSON: %s" % str(e))

    def _onInlineGetTimestamp(self, event=None):
        import time
        ms = int(time.time() * 1000)
        val = str(ms)
        from java.awt.datatransfer import StringSelection
        from java.awt import Toolkit
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection(val), None)
        # Flash the button to give visual feedback
        btn = event.getSource() if event else None
        if btn:
            original_text = btn.getText()
            btn.setText(u"\u2713 Copied!")
            btn.setEnabled(False)
            from javax.swing import Timer as SwingTimer
            def _restore(e):
                btn.setText(original_text)
                btn.setEnabled(True)
            t = SwingTimer(1500, _restore)
            t.setRepeats(False)
            t.start()


# =============================================================================
# Burp Suite Extension Entry Point
