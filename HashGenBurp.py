# -*- coding: utf-8 -*-
# CipherKit - Burp Suite Extension entry point.
# Loaded directly by Burp Suite (Jython). All logic lives in core/ and ui/.

from __future__ import print_function
import os, sys, json, traceback

from burp import (
    IBurpExtender, ITab, IContextMenuFactory, IContextMenuInvocation,
    IMessageEditorTab, IMessageEditorTabFactory, ISessionHandlingAction
)

from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JTextPane, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane, SwingUtilities,
    BorderFactory
)
from javax.swing.border import EmptyBorder

class _WrapPane(JTextPane):
    """JTextPane that wraps text to the viewport width."""
    def getScrollableTracksViewportWidth(self):
        return True

from java.awt import (
    BorderLayout, GridBagLayout, GridBagConstraints, Insets,
    Font, Color, Dimension, FlowLayout, GridLayout
)

# Make sure Burp can find our packages — use callbacks.getExtensionFilename()
# at runtime instead of __file__ (not available in Jython/Burp context)
import inspect as _inspect
_here = os.path.dirname(os.path.abspath(_inspect.getfile(_inspect.currentframe())))
if _here not in sys.path:
    sys.path.insert(0, _here)

from core.snippet_manager import SnippetManager
from core.crypto_snippet_manager import CryptoSnippetManager
from core.app_setting_manager import AppSettingManager, mask_secret, merge_custom_data
from core.body_parser import parse_body, serialize_body, flatten_data
from core.crypto_engine import CryptoEngine
from core.crypto_snippet_engine import CryptoSnippetEngine
from core.utils import _extract_request_path
from ui.editor_tab import HashGenEditorTab
from ui.batch_tab import BatchMapperTab
from ui.components.rounded_border import RoundedBorder, _roundedCompound
from ui.components.custom_data_panel import CustomDataPanel, CompactCustomDataPanel
from ui.components.listeners import PayloadDocumentListener


class _DisabledEditorTab(IMessageEditorTab):
    """Fail-closed IMessageEditorTab placeholder so Burp never receives None."""

    def __init__(self, caption="CipherKit"):
        self._caption = caption
        self._panel = JPanel(BorderLayout())
        self._current_message = None

    def getTabCaption(self):
        return self._caption

    def getUiComponent(self):
        return self._panel

    def isEnabled(self, content, isRequest):
        return False

    def setMessage(self, content, isRequest):
        self._current_message = content

    def getMessage(self):
        return self._current_message

    def isModified(self):
        return False

    def getSelectedData(self):
        return None

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IMessageEditorTabFactory, ISessionHandlingAction):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("CipherKit")

        # Redirect stdout/stderr to Burp's output
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Snippet managers
        ext_file   = callbacks.getExtensionFilename()
        script_dir = os.path.dirname(os.path.abspath(ext_file))
        snippets_path        = os.path.join(script_dir, "snippets.json")
        crypto_snippets_path = os.path.join(script_dir, "crypto_snippets.json")
        app_settings_path = os.path.join(script_dir, "app_settings.json")
        self.snippet_manager        = SnippetManager(snippets_path)
        self.crypto_snippet_manager = CryptoSnippetManager(crypto_snippets_path)
        self.app_setting_manager    = AppSettingManager(app_settings_path)
        self.settings_path = os.path.join(script_dir, "ext_settings.json")
        self.ext_settings = self._load_settings()
        self._lastKfMatches = []
        self._editor_tabs = []  # track active editor tabs
        self._shouldCompareHash = False

        # Build main tab UI synchronously
        SwingUtilities.invokeAndWait(self._buildUI)

        # Register all factories
        callbacks.registerContextMenuFactory(self)
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerSessionHandlingAction(self)  # Intruder Auto-Rehash

        # Register the main HashGen tab
        callbacks.addSuiteTab(self)

        print("[+] CipherKit extension loaded successfully")
        print("[*] Snippets file:       %s" % snippets_path)
        print("[*] Crypto snippets:     %s" % crypto_snippets_path)
        print("[*] App settings file:   %s" % app_settings_path)
        print("[*] CipherKit tab added to request editor views")


    # -------------------------------------------------------------------------
    # ISessionHandlingAction implementation — Intruder Auto-Rehash
    # -------------------------------------------------------------------------
    def getActionName(self):
        """Name shown in Burp Session Handling Rules action picker."""
        return "CipherKit - Auto-Rehash"

    def performAction(self, currentRequest, macroItems):
        """
        Called by Burp Session Handling Rules for every Intruder/Repeater request.
        Finds a matching app setting for the request URL, re-computes the hash field,
        and injects the new value back into the request body.
        """
        try:
            req_info = self._helpers.analyzeRequest(currentRequest.getRequest())
            headers  = req_info.getHeaders()
            body_offset = req_info.getBodyOffset()
            body_bytes  = currentRequest.getRequest()[body_offset:]
            body_str    = self._helpers.bytesToString(body_bytes)

            if not body_str or not body_str.strip():
                return  # nothing to sign

            # Extract URL path for app setting lookup
            url_path = _extract_request_path(req_info)

            # Find a matching app setting
            app_name, app, pattern, ep = self.app_setting_manager.find_by_url(url_path)
            if not app:
                return  # no app setting matched — leave request unchanged

            # Extract content-type
            content_type = ""
            for h in headers:
                if h.lower().startswith("content-type:"):
                    content_type = h[len("content-type:"):].strip()
                    break

            # Parse body
            payload = parse_body(body_str, content_type)
            if not payload:
                return

            # Build params from app setting
            algo_name   = app.get("algorithm", "")
            secret      = app.get("secret", "")
            custom_data = app.get("custom_data", {})
            if ep and "custom_data" in ep:
                custom_data = merge_custom_data(custom_data, ep["custom_data"])
            hash_field  = app.get("hash_field", "hash")
            keys_order  = None
            if ep and ep.get("keys_order"):
                keys_order = [k.strip() for k in ep["keys_order"].split(",") if k.strip()]

            snippet = self.snippet_manager.get_snippet(algo_name)
            if not snippet:
                print("[CipherKit] Auto-Rehash: snippet '%s' not found for app setting '%s'" % (algo_name, app_name))
                return

            result, _ = CryptoEngine.execute_snippet(
                snippet["code"], payload, secret, custom_data, keys_order
            )

            if not result or str(result).startswith("Error"):
                print("[CipherKit] Auto-Rehash error: %s" % result)
                return

            result_str = str(result)
            if self._globalUppercaseHashChk.isSelected():
                result_str = result_str.upper()

            # Inject the new hash back into the body
            payload[hash_field] = result_str
            new_body = serialize_body(payload, body_str, content_type)
            new_body_bytes = self._helpers.stringToBytes(new_body)
            new_request = self._helpers.buildHttpMessage(headers, new_body_bytes)
            currentRequest.setRequest(new_request)

            print("[CipherKit] Auto-Rehash: app_setting='%s' pattern='%s' hash_field='%s' value='%s'" % (
                app_name, pattern, hash_field, result_str[:40]
            ))

        except Exception as e:
            print("[CipherKit] Auto-Rehash exception: %s" % str(e))
            import traceback as _tb
            print(_tb.format_exc())

    # -------------------------------------------------------------------------
    # ITab implementation
    # -------------------------------------------------------------------------
    def getTabCaption(self):
        return "CipherKit"

    def getUiComponent(self):
        return self._mainPanel

    # -------------------------------------------------------------------------
    # IMessageEditorTabFactory implementation
    # -------------------------------------------------------------------------
    def createNewInstance(self, controller, editable):
        try:
            tab = HashGenEditorTab(self, controller, editable)
            self._editor_tabs.append(tab)
            try:
                tab.update_tab_visibility()
            except Exception:
                pass
            return tab
        except Exception as e:
            print("[CipherKit] ERROR creating inline tab: %s" % e)
            print(traceback.format_exc())
            return _DisabledEditorTab()

    # -------------------------------------------------------------------------
    # IContextMenuFactory implementation
    # -------------------------------------------------------------------------
    def createMenuItems(self, invocation):
        from javax.swing import JMenuItem
        menu_items = []

        ctx = invocation.getInvocationContext()
        valid_contexts = [
            IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            IContextMenuInvocation.CONTEXT_PROXY_HISTORY,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            IContextMenuInvocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]

        if ctx in valid_contexts:
            item = JMenuItem("Send to CipherKit")
            item.addActionListener(lambda event: self._onContextMenuSend(invocation))
            menu_items.append(item)

        return menu_items if menu_items else None

    def _onContextMenuSend(self, invocation):
        messages = invocation.getSelectedMessages()
        if messages and len(messages) > 0:
            request = messages[0].getRequest()
            if request:
                analyzed = self._helpers.analyzeRequest(request)
                body_offset = analyzed.getBodyOffset()
                body_bytes = request[body_offset:]
                body_str = self._helpers.bytesToString(body_bytes)

                if body_str and body_str.strip():
                    try:
                        parsed = json.loads(body_str)
                        body_str = json.dumps(parsed, indent=2)
                    except:
                        pass

                    self._payloadArea.setText(body_str)
                    self._tryExtractKeys()

                    parent = self._mainPanel.getParent()
                    if parent:
                        idx = parent.indexOfComponent(self._mainPanel)
                        if idx >= 0:
                            parent.setSelectedIndex(idx)

                    print("[*] Request body sent from context menu")

    # -------------------------------------------------------------------------
    # Build the Main Tab UI
    # -------------------------------------------------------------------------
    def _buildUI(self):
        self._mainPanel = JPanel(BorderLayout())
        self._mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        self._generatorPanel        = self._buildGeneratorTab()   # initialises shared fields; not added as a tab
        self._buildCryptoTab()                                    # initialises shared crypto fields; not added as a tab
        self._buildKeyFinderTab()                                 # initialises shared KF fields; not added as a tab
        self._batchMapperPanel      = BatchMapperTab(self)
        self._settingPanel          = self._buildSettingTab()
        self._extensionSettingPanel = self._buildExtensionSettingTab()

        self.update_tab_visibility()

    # -------------------------------------------------------------------------
    # Generator Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # AppSetting Tab (main CipherKit)
    # -------------------------------------------------------------------------
    def _buildSettingTab(self):
        mainPanel = JPanel(BorderLayout(0, 8))
        mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Top Control Bar (App Setting selector + Hash Field + Default KF Key + Update Value)
        topSectionPanel = JPanel(GridBagLayout())
        topSectionPanel.setBorder(EmptyBorder(0, 0, 4, 0))
        gbc = GridBagConstraints()
        gbc.insets = Insets(3, 4, 3, 4)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.NONE

        # Row 0: App Setting selector + Hash Field Name + Default KF Key
        gbc.gridy = 0; gbc.gridx = 0
        topSectionPanel.add(JLabel("App Setting:"), gbc)
        
        all_app_names = self.app_setting_manager.get_all_names()
        names = ["(none)"] + all_app_names
        self._settingCombo = JComboBox(names)
        self._settingCombo.setPreferredSize(Dimension(180, 26))
        self._settingCombo.addActionListener(lambda e: self._onSettingComboChange())
        
        default_app_name = self.ext_settings.get("default_app", "aba mobile")
        if default_app_name in all_app_names:
            self._settingCombo.setSelectedItem(default_app_name)
        elif "aba mobile" in all_app_names:
            self._settingCombo.setSelectedItem("aba mobile")
        elif all_app_names:
            self._settingCombo.setSelectedItem(all_app_names[0])

        gbc.gridx = 1
        topSectionPanel.add(self._settingCombo, gbc)

        _loadBtn = JButton("Load Config", actionPerformed=self._onSettingSelected)
        _loadBtn.setPreferredSize(Dimension(110, 26))
        gbc.gridx = 2
        topSectionPanel.add(_loadBtn, gbc)

        # Hash Field Name
        gbc.gridx = 3; gbc.insets = Insets(3, 16, 3, 4)
        topSectionPanel.add(JLabel("Hash Field:"), gbc)
        
        gbc.gridx = 4; gbc.insets = Insets(3, 4, 3, 4)
        self._mainHashFieldName.setPreferredSize(Dimension(110, 26))
        topSectionPanel.add(self._mainHashFieldName, gbc)

        # Default KF Key
        gbc.gridx = 5; gbc.insets = Insets(3, 12, 3, 4)
        topSectionPanel.add(JLabel("Default KF Key:"), gbc)

        gbc.gridx = 6; gbc.insets = Insets(3, 4, 3, 4)
        self._mainDefaultKfKey = JTextField("token")
        self._mainDefaultKfKey.setPreferredSize(Dimension(110, 26))
        topSectionPanel.add(self._mainDefaultKfKey, gbc)

        # Trailing filler for Row 0
        gbc.gridx = 7; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        topSectionPanel.add(JPanel(), gbc)

        # Row 1: Update Value form + Action Buttons
        gbc.gridy = 1; gbc.gridx = 0; gbc.gridwidth = 1; gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE; gbc.insets = Insets(3, 4, 3, 4)
        topSectionPanel.add(JLabel("Update Value:"), gbc)

        updateValRow = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        updateValRow.setOpaque(False)
        self._settingCustomKeyField = JTextField("token")
        self._settingCustomKeyField.setPreferredSize(Dimension(110, 26))
        updateValRow.add(self._settingCustomKeyField)
        updateValRow.add(JLabel(":"))
        self._settingCustomValField = JTextField()
        self._settingCustomValField.setPreferredSize(Dimension(160, 26))
        updateValRow.add(self._settingCustomValField)
        self._applyCustomValueBtn = JButton("Update", actionPerformed=self._onApplyCustomValue)
        self._applyCustomValueBtn.setPreferredSize(Dimension(80, 26))
        updateValRow.add(self._applyCustomValueBtn)

        gbc.gridx = 1; gbc.gridwidth = 2
        topSectionPanel.add(updateValRow, gbc)

        # Action Buttons (Save New, Update Existing, Delete App)
        actRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
        actRow.setOpaque(False)
        self._saveNewSettingBtn   = JButton("Save New", actionPerformed=self._onSaveNewSetting)
        self._updateSettingBtn    = JButton("Update Existing", actionPerformed=self._onUpdateSetting)
        self._deleteSettingBtn    = JButton("Delete App", actionPerformed=self._onDeleteSetting)
        actRow.add(self._saveNewSettingBtn)
        actRow.add(self._updateSettingBtn)
        actRow.add(self._deleteSettingBtn)

        gbc.gridx = 3; gbc.gridwidth = 4; gbc.insets = Insets(3, 16, 3, 4)
        topSectionPanel.add(actRow, gbc)

        # Trailing filler for Row 1
        gbc.gridx = 7; gbc.gridwidth = 1; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.insets = Insets(3, 4, 3, 4)
        topSectionPanel.add(JPanel(), gbc)

        mainPanel.add(topSectionPanel, BorderLayout.NORTH)

        # Center: Full-height Monospace Summary & Endpoints Table Area
        self._settingSummaryArea = JTextArea()
        self._settingSummaryArea.setEditable(False)
        self._settingSummaryArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._settingSummaryArea.setBorder(EmptyBorder(5, 5, 5, 5))
        mainPanel.add(JScrollPane(self._settingSummaryArea), BorderLayout.CENTER)

        self._refreshSettingSummary()
        return mainPanel

    # -------------------------------------------------------------------------
    # Extension Setting Tab (main CipherKit)
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Extension Setting Tab (main CipherKit)
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Extension Setting Tab (main CipherKit)
    # -------------------------------------------------------------------------
    def _buildExtensionSettingTab(self):
        mainPanel = JPanel(BorderLayout(0, 10))
        mainPanel.setBorder(EmptyBorder(12, 12, 12, 12))

        boxPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(0, 0, 10, 0)
        gbc.anchor = GridBagConstraints.NORTHWEST
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0

        # --- Section 1: Tab & Profile Settings ---
        tabsPanel = JPanel(GridBagLayout())
        tabsPanel.setBorder(BorderFactory.createTitledBorder("Tab & Profile Settings"))
        tgbc = GridBagConstraints()
        tgbc.insets = Insets(5, 12, 5, 12)
        tgbc.anchor = GridBagConstraints.WEST
        tgbc.fill = GridBagConstraints.NONE

        tgbc.gridy = 0; tgbc.gridx = 0; tgbc.gridwidth = 2
        self._optShowAs = JCheckBox("Enable AppSetting Tab", self.ext_settings.get("show_app_setting", True))
        tabsPanel.add(self._optShowAs, tgbc)

        tgbc.gridy = 1; tgbc.gridx = 0; tgbc.gridwidth = 2
        self._optShowBatch = JCheckBox("Enable Batch Mapper Tab", self.ext_settings.get("show_batch_mapper", True))
        tabsPanel.add(self._optShowBatch, tgbc)

        tgbc.gridy = 2; tgbc.gridx = 0; tgbc.gridwidth = 2
        self._optShowCrypto = JCheckBox("Enable Crypto Tab in Request Tab", self.ext_settings.get("show_crypto", False))
        tabsPanel.add(self._optShowCrypto, tgbc)

        tgbc.gridy = 3; tgbc.gridx = 0; tgbc.gridwidth = 1
        tabsPanel.add(JLabel("Default Load App:"), tgbc)
        tgbc.gridx = 1
        names = ["(none)"] + self.app_setting_manager.get_all_names()
        self._optDefaultAppCombo = JComboBox(names)
        self._optDefaultAppCombo.setPreferredSize(Dimension(180, 26))
        self._optDefaultAppCombo.setSelectedItem(self.ext_settings.get("default_app", "aba mobile"))
        tabsPanel.add(self._optDefaultAppCombo, tgbc)

        # Trailing horizontal filler to push controls left
        tgbc.gridy = 0; tgbc.gridx = 2; tgbc.gridwidth = 1; tgbc.gridheight = 4; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        tabsPanel.add(JPanel(), tgbc)

        gbc.gridy = 0; gbc.gridx = 0
        boxPanel.add(tabsPanel, gbc)

        # --- Section 2: Inline Request Editor Buttons ---
        buttonsPanel = JPanel(GridBagLayout())
        buttonsPanel.setBorder(BorderFactory.createTitledBorder("Inline Request Editor Buttons"))
        bgbc = GridBagConstraints()
        bgbc.insets = Insets(5, 12, 5, 12)
        bgbc.anchor = GridBagConstraints.WEST
        bgbc.fill = GridBagConstraints.NONE

        bgbc.gridy = 0; bgbc.gridx = 0; bgbc.gridwidth = 2
        self._optShowRunHashBtn = JCheckBox("Enable Run Hash Button", self.ext_settings.get("show_run_hash", True))
        buttonsPanel.add(self._optShowRunHashBtn, bgbc)

        bgbc.gridy = 1; bgbc.gridx = 0; bgbc.gridwidth = 2
        self._optShowTsBtn = JCheckBox("Enable Get Timestamp Button", self.ext_settings.get("show_get_timestamp", False))
        buttonsPanel.add(self._optShowTsBtn, bgbc)

        # Trailing horizontal filler to push controls left
        bgbc.gridy = 0; bgbc.gridx = 2; bgbc.gridwidth = 1; bgbc.gridheight = 2; bgbc.weightx = 1.0; bgbc.fill = GridBagConstraints.HORIZONTAL
        buttonsPanel.add(JPanel(), bgbc)

        gbc.gridy = 1; gbc.gridx = 0
        boxPanel.add(buttonsPanel, gbc)

        # --- Section 3: Hash & Encryption Output Rules ---
        sessionPanel = JPanel(GridBagLayout())
        sessionPanel.setBorder(BorderFactory.createTitledBorder("Hash & Encryption Output Rules"))
        sgbc = GridBagConstraints()
        sgbc.insets = Insets(5, 12, 5, 12)
        sgbc.anchor = GridBagConstraints.WEST
        sgbc.fill = GridBagConstraints.NONE

        # Row 0: Active Output Mode
        sgbc.gridy = 0; sgbc.gridx = 0
        sessionPanel.add(JLabel("Hash tab output:"), sgbc)
        sgbc.gridx = 1
        self._activeOutputCombo = JComboBox(["Hash", "Crypto"])
        self._activeOutputCombo.setPreferredSize(Dimension(180, 26))
        self._activeOutputCombo.setToolTipText(
            "Hash: output shows the generated hash value\n"
            "Crypto: output shows decrypted field value (editable, auto-encrypts on change)"
        )
        sessionPanel.add(self._activeOutputCombo, sgbc)

        # Row 1: Auto-encrypt on edit
        sgbc.gridy = 1; sgbc.gridx = 0; sgbc.gridwidth = 2
        self._globalAutoEncryptChk = JCheckBox("Auto-encrypt on edit", True)
        sessionPanel.add(self._globalAutoEncryptChk, sgbc)

        # Row 2: Uppercase hash
        sgbc.gridy = 2; sgbc.gridx = 0; sgbc.gridwidth = 2
        self._globalUppercaseHashChk = JCheckBox("Uppercase hash", True)
        sessionPanel.add(self._globalUppercaseHashChk, sgbc)

        # Trailing horizontal filler to push controls left
        sgbc.gridy = 0; sgbc.gridx = 2; sgbc.gridwidth = 1; sgbc.gridheight = 3; sgbc.weightx = 1.0; sgbc.fill = GridBagConstraints.HORIZONTAL
        sessionPanel.add(JPanel(), sgbc)

        gbc.gridy = 2; gbc.gridx = 0
        boxPanel.add(sessionPanel, gbc)

        # --- Save Settings Button Row ---
        btnRow = JPanel(FlowLayout(FlowLayout.LEFT, 12, 8))
        saveOptBtn = JButton("Save Extension Settings", actionPerformed=self._onSaveExtensionSettings)
        saveOptBtn.setPreferredSize(Dimension(180, 28))
        btnRow.add(saveOptBtn)

        gbc.gridy = 3; gbc.gridx = 0; gbc.insets = Insets(5, 0, 0, 0)
        boxPanel.add(btnRow, gbc)

        # Trailing vertical filler to anchor content nicely at top
        gbc.gridy = 4; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH
        boxPanel.add(JPanel(), gbc)

        mainPanel.add(boxPanel, BorderLayout.NORTH)
        return mainPanel




    def _buildGeneratorTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # --- Top side: compact inputs in 4 columns ---
        topPanel = JPanel(GridBagLayout())
        topPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        tgbc = GridBagConstraints()
        tgbc.insets = Insets(4, 5, 4, 5)
        tgbc.fill = GridBagConstraints.HORIZONTAL
        tgbc.weightx = 0.5
        tgbc.gridy = 0

        names = self.snippet_manager.get_all_names()
        if not names:
            names = ["Default"]
        self._algoCombo = JComboBox(names)
        self._algoCombo.addActionListener(lambda e: self._updatePasscodeFieldState())
        
        self._passcodeField = JTextField()
        self._passcodeLabel = JLabel("Secret:")
        
        self._customDataPanel = CustomDataPanel()
        
        self._keysOrderField = JTextField()
        
        self._mainHashFieldName = JTextField("hash")
        self._mainHashFieldName.setToolTipText("JSON key name where the output will be injected")
        
        self._generateBtn = JButton("Generate", actionPerformed=self._onGenerate)

        # Row 0: Algo & Secret
        tgbc.gridy = 0
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Algorithm:"), tgbc)
        tgbc.gridx = 1; tgbc.weightx = 0.5; tgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._algoCombo, tgbc)
        
        tgbc.gridx = 2; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE; tgbc.insets = Insets(4, 16, 4, 5)
        topPanel.add(self._passcodeLabel, tgbc)
        tgbc.gridx = 3; tgbc.weightx = 0.5; tgbc.fill = GridBagConstraints.HORIZONTAL; tgbc.insets = Insets(4, 5, 4, 5)
        topPanel.add(self._passcodeField, tgbc)
        
        SwingUtilities.invokeLater(lambda: self._updatePasscodeFieldState())

        # Row 1: Sign Order (spans columns 1-3)
        tgbc.gridy = 1
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Sign Order:"), tgbc)
        tgbc.gridx = 1; tgbc.gridwidth = 3; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._keysOrderField, tgbc)
        tgbc.gridwidth = 1  # restore

        # Row 2: Custom Data (spans columns 1-3)
        tgbc.gridy = 2
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE; tgbc.anchor = GridBagConstraints.NORTHWEST
        topPanel.add(JLabel("Custom Data:"), tgbc)
        tgbc.gridx = 1; tgbc.gridwidth = 3; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL; tgbc.anchor = GridBagConstraints.WEST
        topPanel.add(self._customDataPanel, tgbc)
        tgbc.gridwidth = 1  # restore

        # Row 3: Buttons (spans columns 0-3)
        tgbc.gridy = 3
        tgbc.gridx = 0; tgbc.gridwidth = 4; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        tgbc.insets = Insets(8, 5, 4, 5)
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0))
        btnPanel.add(self._generateBtn)
        topPanel.add(btnPanel, tgbc)

        # --- Bottom side: text areas with label above each box ---
        bottomPanel = JPanel(GridBagLayout())
        bottomPanel.setBorder(EmptyBorder(0, 0, 0, 0))
        gbc = GridBagConstraints()
        gbc.gridx   = 0
        gbc.weightx = 1.0
        gbc.fill    = GridBagConstraints.HORIZONTAL
        gbc.insets  = Insets(0, 0, 2, 0)

        # Payload label
        gbc.gridy  = 0; gbc.weighty = 0
        bottomPanel.add(JLabel("Payload:"), gbc)

        # Payload text area
        gbc.gridy  = 1; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._payloadArea = JTextArea(12, 40)
        self._payloadArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._payloadArea.setLineWrap(True)
        self._payloadArea.setWrapStyleWord(True)
        self._payloadArea.setText('{\n  "username": "user",\n  "request_time": "20260101010101"\n}')
        self._payloadArea.getDocument().addDocumentListener(
            PayloadDocumentListener(self._tryExtractKeys)
        )
        payloadScroll = JScrollPane(self._payloadArea)
        payloadScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bottomPanel.add(payloadScroll, gbc)

        # Result Hash label
        gbc.gridy  = 2; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        resHashLabelPanel = JPanel(FlowLayout(FlowLayout.LEFT, 5, 0))
        resHashLabelPanel.add(JLabel("Result Hash:"))
        self._mainStatusLabel = JLabel("")
        resHashLabelPanel.add(self._mainStatusLabel)
        bottomPanel.add(resHashLabelPanel, gbc)

        # Result Hash text area
        gbc.gridy  = 3; gbc.weighty = 0.2; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 8, 0)
        self._outputArea = JTextArea(3, 40)
        self._outputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._outputArea.setLineWrap(True)
        self._outputArea.setWrapStyleWord(True)
        self._outputArea.setEditable(False)
        outputScroll = JScrollPane(self._outputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bottomPanel.add(outputScroll, gbc)

        # Debug Output label
        gbc.gridy  = 4; gbc.weighty = 0; gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.insets = Insets(0, 0, 2, 0)
        bottomPanel.add(JLabel("Debug Output:"), gbc)

        # Debug text area
        gbc.gridy  = 5; gbc.weighty = 0.6; gbc.fill = GridBagConstraints.BOTH
        gbc.insets = Insets(0, 0, 0, 0)
        self._debugArea = JTextArea(6, 40)
        self._debugArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._debugArea.setForeground(Color(40, 40, 40))
        self._debugArea.setLineWrap(True)
        self._debugArea.setWrapStyleWord(True)
        self._debugArea.setEditable(False)
        debugScroll = JScrollPane(self._debugArea)
        debugScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bottomPanel.add(debugScroll, gbc)

        panel.add(topPanel, BorderLayout.NORTH)
        panel.add(bottomPanel, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # Crypto Tab (AES-CBC-128 Encrypt / Decrypt)
    # -------------------------------------------------------------------------
    def _buildCryptoTab(self):
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- Top config panel ----
        topPanel = JPanel(GridBagLayout())
        topPanel.setBorder(
            _roundedCompound(radius=8, padding=10)
        )

        cgbc = GridBagConstraints()
        cgbc.insets  = Insets(4, 4, 4, 4)
        cgbc.fill    = GridBagConstraints.HORIZONTAL
        cgbc.weightx = 0.5

        self._cryptoModeCombo = JComboBox(["Encrypt", "Decrypt"])
        
        crypto_names = self.crypto_snippet_manager.get_all_names()
        if not crypto_names:
            crypto_names = ["(no algorithms -- add via Crypto Editor)"]
        self._cryptoAlgoCombo = JComboBox(crypto_names)
        self._cryptoAlgoCombo.addActionListener(lambda e: self._updateCryptoFieldState())
        
        self._cryptoKeyField = JTextField()
        self._cryptoIvField = JTextField()
        
        self._mainCryptoField = JTextField("data")
        self._mainCryptoField.setToolTipText("JSON key to read input from / write output to")
        
        self._cryptoRunBtn = JButton("Run Crypto", actionPerformed=self._onCryptoRun)

        # Row 0: Mode & Algorithm
        cgbc.gridy = 0
        cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Mode:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._cryptoModeCombo, cgbc)
        
        cgbc.gridx = 2; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE; cgbc.insets = Insets(4, 16, 4, 4)
        topPanel.add(JLabel("Algorithm:"), cgbc)
        cgbc.gridx = 3; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL; cgbc.insets = Insets(4, 4, 4, 4)
        topPanel.add(self._cryptoAlgoCombo, cgbc)

        # Row 1: Key & IV
        cgbc.gridy = 1
        cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Key:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._cryptoKeyField, cgbc)
        
        cgbc.gridx = 2; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE; cgbc.insets = Insets(4, 16, 4, 4)
        topPanel.add(JLabel("IV:"), cgbc)
        cgbc.gridx = 3; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL; cgbc.insets = Insets(4, 4, 4, 4)
        topPanel.add(self._cryptoIvField, cgbc)

        # Row 2: Field & Run Button
        cgbc.gridy = 2
        cgbc.gridx = 0; cgbc.weightx = 0; cgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Field:"), cgbc)
        cgbc.gridx = 1; cgbc.weightx = 0.5; cgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._mainCryptoField, cgbc)
        
        cgbc.gridx = 2; cgbc.gridwidth = 2; cgbc.weightx = 1.0; cgbc.fill = GridBagConstraints.HORIZONTAL; cgbc.insets = Insets(4, 16, 4, 4)
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0))
        btnPanel.add(self._cryptoRunBtn)
        topPanel.add(btnPanel, cgbc)
        cgbc.gridwidth = 1  # restore

        # ---- Bottom: input + output text areas ----
        bottomPanel = JPanel(GridBagLayout())
        rgbc = GridBagConstraints()
        rgbc.fill    = GridBagConstraints.BOTH
        rgbc.insets  = Insets(2, 0, 2, 0)
        rgbc.gridx   = 0
        rgbc.weightx = 1.0

        # Input label
        rgbc.gridy  = 0
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        inputLbl    = JLabel("Input (plaintext for Encrypt, Base64 for Decrypt):")
        bottomPanel.add(inputLbl, rgbc)

        # Input text area
        rgbc.gridy  = 1
        rgbc.weighty = 1.0
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoInputArea = JTextArea(10, 40)
        self._cryptoInputArea.setLineWrap(True)
        self._cryptoInputArea.setWrapStyleWord(True)
        inputScroll = JScrollPane(self._cryptoInputArea)
        inputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bottomPanel.add(inputScroll, rgbc)

        # Output label
        rgbc.gridy  = 2
        rgbc.weighty = 0
        rgbc.fill   = GridBagConstraints.HORIZONTAL
        outputLbl   = JLabel("Output:")
        bottomPanel.add(outputLbl, rgbc)

        # Output text area
        rgbc.gridy  = 3
        rgbc.weighty = 0.4
        rgbc.fill   = GridBagConstraints.BOTH
        self._cryptoOutputArea = JTextArea(4, 40)
        self._cryptoOutputArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._cryptoOutputArea.setEditable(False)
        self._cryptoOutputArea.setLineWrap(True)
        self._cryptoOutputArea.setWrapStyleWord(True)
        outputScroll = JScrollPane(self._cryptoOutputArea)
        outputScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bottomPanel.add(outputScroll, rgbc)

        panel.add(topPanel, BorderLayout.NORTH)
        panel.add(bottomPanel, BorderLayout.CENTER)

        return panel

    # -------------------------------------------------------------------------
    # UI State Helpers: requires_key / requires_iv field visibility
    # -------------------------------------------------------------------------
    def _updatePasscodeFieldState(self):
        """Dim/enable the Secret field in the Hash tab based on requires_key flag."""
        try:
            name    = str(self._algoCombo.getSelectedItem())
            snippet = self.snippet_manager.get_snippet(name)
            needs   = True  # default: key required
            if snippet:
                needs = snippet.get("requires_key", True)
            gray = Color(160, 160, 160)
            black = Color(0, 0, 0)
            if needs:
                self._passcodeField.setEditable(True)
                self._passcodeField.setForeground(black)
                self._passcodeField.setToolTipText(None)
                self._passcodeLabel.setForeground(black)
            else:
                self._passcodeField.setEditable(False)
                self._passcodeField.setForeground(gray)
                self._passcodeField.setToolTipText("Not used for " + name)
                self._passcodeField.setText("")
                self._passcodeLabel.setForeground(gray)
        except Exception:
            pass

    def _updateCryptoFieldState(self):
        """Show/dim Key and IV fields based on the selected crypto algo's flags."""
        try:
            name     = str(self._cryptoAlgoCombo.getSelectedItem())
            needs_k  = self.crypto_snippet_manager.requires_key(name)
            needs_iv = self.crypto_snippet_manager.requires_iv(name)
            gray  = Color(160, 160, 160)
            black = Color(0, 0, 0)
            self._cryptoKeyField.setEditable(needs_k)
            self._cryptoKeyField.setForeground(black if needs_k else gray)
            self._cryptoKeyField.setToolTipText(
                None if needs_k else "Key not required for " + name
            )
            self._cryptoIvField.setEditable(needs_iv)
            self._cryptoIvField.setForeground(black if needs_iv else gray)
            self._cryptoIvField.setToolTipText(
                None if needs_iv else "IV not required for " + name
            )
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # AppSetting Actions
    # -------------------------------------------------------------------------
    def _onSettingSelected(self):
        """Load selected app setting into Hash + Crypto main tab fields."""
        try:
            name = str(self._settingCombo.getSelectedItem())
            if name == "(none)":
                return
            app = self.app_setting_manager.get_app(name)
            if not app:
                return
            if app.get("algorithm"):
                self._algoCombo.setSelectedItem(app["algorithm"])
            if "secret" in app:
                self._passcodeField.setText(app["secret"])
            if app.get("custom_data"):
                self._customDataPanel.setPairs(app["custom_data"])
            if "hash_field" in app:
                self._mainHashFieldName.setText(app["hash_field"])
            if "default_kf_key" in app:
                self._mainDefaultKfKey.setText(app["default_kf_key"])
            else:
                self._mainDefaultKfKey.setText("token")
            # keys_order: show first endpoint's value if available
            endpoints = app.get("endpoints", {})
            if endpoints:
                first_ep = list(endpoints.values())[0]
                self._keysOrderField.setText(first_ep.get("keys_order", ""))
                if "custom_data" in first_ep:
                    self._customDataPanel.setPairs(first_ep["custom_data"])
            # Crypto config
            c = app.get("crypto", {})
            if c.get("mode"):
                self._cryptoModeCombo.setSelectedItem(c["mode"])
            if c.get("algorithm"):
                self._cryptoAlgoCombo.setSelectedItem(c["algorithm"])
            if "key" in c:
                self._cryptoKeyField.setText(c["key"])
            if "iv" in c:
                self._cryptoIvField.setText(c["iv"])
            if "field" in c:
                self._mainCryptoField.setText(c["field"])
        except Exception as e:
            print("[CipherKit] Setting load error: %s" % str(e))

    def _onSaveNewSetting(self, event=None):
        """Save current config as a new app-level setting."""
        name = JOptionPane.showInputDialog(
            self._mainPanel, "App setting name:", "Save Setting",
            JOptionPane.PLAIN_MESSAGE, None, None, ""
        )
        if not name or not str(name).strip():
            return
        name = str(name).strip()
        app_data = self._getAppSettingData()
        self.app_setting_manager.save_app(name, app_data)
        self._refreshSettingCombo()
        self._settingCombo.setSelectedItem(name)
        self._refreshSettingSummary()
        print("[CipherKit] AppSetting saved: %s" % name)

    def _onDeleteSetting(self, event=None):
        """Delete the selected app setting."""
        name = str(self._settingCombo.getSelectedItem())
        if name == "(none)":
            return
        confirm = JOptionPane.showConfirmDialog(
            self._mainPanel, "Delete app setting '%s' and all its endpoints?" % name,
            "Delete Setting", JOptionPane.YES_NO_OPTION
        )
        if confirm == JOptionPane.YES_OPTION:
            self.app_setting_manager.delete_app(name)
            self._refreshSettingCombo()
            self._refreshSettingSummary()
            print("[CipherKit] AppSetting deleted: %s" % name)

    def _onUpdateSetting(self, event=None):
        """Update the selected app setting with current config."""
        name = str(self._settingCombo.getSelectedItem())
        if name == "(none)":
            JOptionPane.showMessageDialog(self._mainPanel,
                "Select an app setting first.", "Update Setting",
                JOptionPane.INFORMATION_MESSAGE)
            return
        app_data = self._getAppSettingData()
        self.app_setting_manager.save_app(name, app_data)
        self._refreshSettingSummary()
        print("[CipherKit] AppSetting updated: %s" % name)

    def _getAppSettingData(self):
        """Helper to collect current UI fields for saving to AppSetting."""
        return {
            "algorithm":   str(self._algoCombo.getSelectedItem()),
            "secret":      self._passcodeField.getText(),
            "custom_data": self._customDataPanel.getPairs(),
            "hash_field":  self._mainHashFieldName.getText().strip() or "hash",
            "default_kf_key": self._mainDefaultKfKey.getText().strip() or "token",
            "crypto": {
                "mode":      str(self._cryptoModeCombo.getSelectedItem()),
                "algorithm": str(self._cryptoAlgoCombo.getSelectedItem()),
                "key":       self._cryptoKeyField.getText(),
                "iv":        self._cryptoIvField.getText(),
                "field":     self._mainCryptoField.getText().strip() or "data",
            },
        }

    def _onApplyCustomValue(self, event=None):
        """Update the custom data key + value across all endpoints of the currently selected app."""
        name = str(self._settingCombo.getSelectedItem())
        if name == "(none)":
            JOptionPane.showMessageDialog(self._panel, "Please select an app setting first.",
                                          "Apply Custom Value", JOptionPane.WARNING_MESSAGE)
            return
        app = self.app_setting_manager.get_app(name)
        if not app:
            JOptionPane.showMessageDialog(self._panel, "App configuration not found.",
                                          "Apply Custom Value", JOptionPane.ERROR_MESSAGE)
            return

        key_name = self._settingCustomKeyField.getText().strip()
        if not key_name:
            JOptionPane.showMessageDialog(self._panel, "Please enter a key name.",
                                          "Apply Custom Value", JOptionPane.WARNING_MESSAGE)
            return

        new_val = self._settingCustomValField.getText() # allow empty string

        # Step 3 – update wherever the key appears
        count = 0
        # Shared custom_data
        shared = app.get("custom_data", {})
        if key_name in shared:
            shared[key_name] = new_val
            count += 1
        # Per-endpoint custom_data
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

        # Persist changes (app dict is a live reference, just call save())
        self.app_setting_manager.save()
        self._refreshSettingSummary()

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

    def _onSettingComboChange(self, event=None):
        self._refreshSettingSummary()

    def _refreshSettingCombo(self):
        """Refresh the main setting combo box with current app names."""
        names = self.app_setting_manager.get_all_names()
        current = str(self._settingCombo.getSelectedItem()) if hasattr(self, '_settingCombo') and self._settingCombo else None
        HashGenEditorTab._refill_setting_combo(self._settingCombo, names)
        if hasattr(self, '_optDefaultAppCombo'):
            HashGenEditorTab._refill_setting_combo(self._optDefaultAppCombo, names)

        if not current or current == "(none)":
            default_name = self.ext_settings.get("default_app", "aba mobile")
            if default_name in names:
                self._settingCombo.setSelectedItem(default_name)
            elif "aba mobile" in names:
                self._settingCombo.setSelectedItem("aba mobile")
            elif names:
                self._settingCombo.setSelectedItem(names[0])
        self._refreshSettingSummary()

    def _refreshSettingSummary(self):
        """Refresh the AppSetting tab summary text area with the selected app's config."""
        try:
            name = str(self._settingCombo.getSelectedItem())
            if name == "(none)":
                self._settingSummaryArea.setText("(no setting selected)")
                return
            app = self.app_setting_manager.get_app(name)
            if not app:
                self._settingSummaryArea.setText("(setting not found)")
                return
            lines = []
            lines.append("App Setting : %s" % name)
            lines.append("")
            lines.append("Shared Config")
            lines.append("-" * 44)
            lines.append("  Algorithm     : %s" % app.get("algorithm", ""))
            lines.append("  Secret        : %s" % mask_secret(app.get("secret", "")))
            lines.append("  Hash Field    : %s" % app.get("hash_field", ""))
            lines.append("  Default KF Key: %s" % app.get("default_kf_key", "token"))
            custom_data = app.get("custom_data", {})
            if custom_data:
                custom_str = ", ".join("%s=%s" % (k, v) for k, v in custom_data.items())
                lines.append("  Custom Data: %s" % custom_str)
            c = app.get("crypto", {})
            if c:
                lines.append("")
                lines.append("  Crypto")
                lines.append("    Algorithm: %s" % c.get("algorithm", ""))
                lines.append("    Key      : %s" % mask_secret(c.get("key", "")))
                lines.append("    IV       : %s" % mask_secret(c.get("iv", "")))
                lines.append("    Field    : %s" % c.get("field", ""))
            endpoints = app.get("endpoints", {})
            if endpoints:
                lines.append("")
                lines.append("Endpoints (Alphabetical Order)")
                lines.append("=" * 80)
                lines.append("  %-32s | %-32s | %s" % ("Endpoint URL Path", "Sign Order", "Custom Data"))
                lines.append("  " + "-" * 32 + "-+-" + "-" * 32 + "-+-" + "-" * 15)
                for pat, ep in sorted(endpoints.items(), key=lambda x: str(x[0]).lower()):
                    keys_order = ep.get("keys_order", "")
                    custom_str = ""
                    if "custom_data" in ep and ep["custom_data"]:
                        custom_str = ", ".join("%s=%s" % (k, v) for k, v in ep["custom_data"].items())
                    lines.append("  %-32s | %-32s | %s" % (pat, keys_order, custom_str))
            else:
                lines.append("")
                lines.append("No endpoints saved yet.")
            self._settingSummaryArea.setText("\n".join(lines))
            self._settingSummaryArea.setCaretPosition(0)
        except Exception as e:
            print("[CipherKit] AppSetting summary error: %s" % str(e))

    def _setKfResultStyled(self, text):
        """Write text to the KF result JTextPane. Key order result lines are shown
        in JSON-key blue without the 'Key order :' prefix."""
        from javax.swing.text import SimpleAttributeSet, StyleConstants
        doc = self._kfResultArea.getStyledDocument()
        doc.remove(0, doc.getLength())
        normal = SimpleAttributeSet()
        StyleConstants.setFontFamily(normal, "Monospaced")
        StyleConstants.setFontSize(normal, 12)
        StyleConstants.setForeground(normal, Color(30, 30, 30))
        highlight = SimpleAttributeSet()
        StyleConstants.setFontFamily(highlight, "Monospaced")
        StyleConstants.setFontSize(highlight, 12)
        StyleConstants.setForeground(highlight, Color(0, 85, 170))
        for line in text.splitlines():
            if line.startswith("Key order :"):
                display = line[len("Key order :"):].strip()
                doc.insertString(doc.getLength(), display + "\n", highlight)
            else:
                doc.insertString(doc.getLength(), line + "\n", normal)

    # -------------------------------------------------------------------------
    # Snippet Editor Tab
    # -------------------------------------------------------------------------
    # -------------------------------------------------------------------------
    # Key Order Finder Tab
    # -------------------------------------------------------------------------
    def _buildKeyFinderTab(self):
        """
        Reverse-engineer key concatenation order.
        Given a JSON / form-data body and a known concatenated string,
        find which permutation of the field values produces that string.
        """
        panel = JPanel(BorderLayout(10, 10))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # ---- Top config panel ----
        topPanel = JPanel(GridBagLayout())
        topPanel.setBorder(_roundedCompound(radius=8, padding=10))

        tgbc = GridBagConstraints()
        tgbc.insets = Insets(4, 5, 4, 5)
        tgbc.fill = GridBagConstraints.HORIZONTAL
        tgbc.weightx = 0.5
        tgbc.gridy = 0

        self._kfFormatCombo = JComboBox(["Auto-Detect", "JSON", "Form Data", "Multipart"])
        
        self._kfAdditionalPanel = CompactCustomDataPanel()
        self._kfAdditionalPanel._rows[0][0].setText("token")  # default key = token
        self._kfAdditionalPanel.setToolTipText("Extra fields not in the request body, e.g. token: <value>")
        
        self._kfKnownArea = JTextField()
        self._kfKnownArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        
        # Row 0: Body Format & Extra Fields
        tgbc.gridy = 0
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Body Format:"), tgbc)
        tgbc.gridx = 1; tgbc.weightx = 0.5; tgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._kfFormatCombo, tgbc)
        
        tgbc.gridx = 2; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE; tgbc.insets = Insets(4, 16, 4, 5)
        topPanel.add(JLabel("Extra Fields:"), tgbc)
        tgbc.gridx = 3; tgbc.weightx = 0.5; tgbc.fill = GridBagConstraints.HORIZONTAL; tgbc.insets = Insets(4, 5, 4, 5)
        topPanel.add(self._kfAdditionalPanel, tgbc)

        # Row 1: Known String
        tgbc.gridy = 1
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE; tgbc.insets = Insets(4, 5, 4, 5)
        topPanel.add(JLabel("Known String:"), tgbc)
        tgbc.gridx = 1; tgbc.gridwidth = 3; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._kfKnownArea, tgbc)
        tgbc.gridwidth = 1  # restore

        # Row 2: Buttons
        tgbc.gridy = 2
        tgbc.gridx = 0; tgbc.gridwidth = 4; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        tgbc.insets = Insets(8, 5, 4, 5)
        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 4, 0))
        parseBtn = JButton("Parse Body", actionPerformed=self._onParseKeyFinderBody)
        parseBtn.setToolTipText("Parse the request body and populate Parsed Fields below")
        findBtn = JButton("Find Key Order", actionPerformed=self._onFindOrder)
        self._kfApplyBtn = JButton("Apply to Hash Tab", actionPerformed=self._onApplyKfResult)
        self._kfApplyBtn.setEnabled(False)
        btnPanel.add(parseBtn)
        btnPanel.add(findBtn)
        btnPanel.add(self._kfApplyBtn)
        topPanel.add(btnPanel, tgbc)

        # ---- Bottom side: side-by-side equal columns ----
        bottomPanel = JPanel(GridLayout(1, 3, 10, 0))

        # Column 1: Request Body
        bodyCol = JPanel(BorderLayout(0, 4))
        bodyCol.add(JLabel("Request Body (paste here):"), BorderLayout.NORTH)
        self._kfBodyArea = JTextArea(12, 20)
        self._kfBodyArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfBodyArea.setLineWrap(True)
        self._kfBodyArea.setWrapStyleWord(True)
        bodyScroll = JScrollPane(self._kfBodyArea)
        bodyScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        bodyCol.add(bodyScroll, BorderLayout.CENTER)
        bottomPanel.add(bodyCol)

        # Column 2: Parsed Fields
        parsedCol = JPanel(BorderLayout(0, 4))
        parsedCol.add(JLabel("Parsed Fields (key: value):"), BorderLayout.NORTH)
        self._kfParsedArea = JTextArea(8, 20)
        self._kfParsedArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfParsedArea.setEditable(True)
        self._kfParsedArea.setLineWrap(True)
        self._kfParsedArea.setToolTipText("Auto-filled by Parse Body, or edit manually")
        parsedScroll = JScrollPane(self._kfParsedArea)
        parsedScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        parsedCol.add(parsedScroll, BorderLayout.CENTER)
        bottomPanel.add(parsedCol)

        # Column 3: Results
        resultCol = JPanel(BorderLayout(0, 4))
        resultCol.add(JLabel("Results:"), BorderLayout.NORTH)
        self._kfResultArea = _WrapPane()
        self._kfResultArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._kfResultArea.setEditable(False)
        resultScroll = JScrollPane(self._kfResultArea)
        resultScroll.setBorder(RoundedBorder(8, Color(180, 180, 180)))
        resultCol.add(resultScroll, BorderLayout.CENTER)
        bottomPanel.add(resultCol)

        panel.add(topPanel, BorderLayout.NORTH)
        panel.add(bottomPanel, BorderLayout.CENTER)
        return panel

    def _onParseKeyFinderBody(self, event=None):
        """Parse the body textarea and populate the Parsed Fields textarea."""
        body = self._kfBodyArea.getText().strip()
        fmt  = str(self._kfFormatCombo.getSelectedItem())
        try:
            pairs = self._kfParseBody(body, fmt)
            if not pairs:
                self._kfParsedArea.setText("(no fields found)")
                return
            lines = ["%s: %s" % (k, v) for k, v in pairs.items()]
            self._kfParsedArea.setText("\n".join(lines))
        except Exception as e:
            self._kfParsedArea.setText("Parse error: %s" % str(e))

    def _kfParseBody(self, body, fmt):
        """Return OrderedDict-like list of (key, value) from JSON, form data or multipart."""
        if fmt == "JSON":
            ct = "application/json"
        elif fmt == "Form Data":
            ct = "application/x-www-form-urlencoded"
        elif fmt == "Multipart":
            ct = "multipart/form-data"
        else:
            ct = ""  # Auto-Detect
        
        data = parse_body(body, ct)
        return flatten_data(data)

    def _kfReadParsedFields(self):
        """Read the manually-editable Parsed Fields and Additional Values areas back into an OrderedDict."""
        from collections import OrderedDict
        pairs = OrderedDict()
        
        # Read from Parsed Fields
        text1 = self._kfParsedArea.getText().strip()
        for line in text1.splitlines():
            line = line.strip()
            if ":" in line:
                k, _, v = line.partition(":")
                pairs[k.strip()] = v.strip()
                
        # Read from Extra Fields panel (N-06: CompactCustomDataPanel)
        for k, v in self._kfAdditionalPanel.getPairs().items():
            if k:
                pairs[k] = v
                
        return pairs

    def _onFindOrder(self, event=None):
        """
        Bug-2 fix: brute-force runs in a background thread to avoid freezing Burp.
        UI updates are dispatched via SwingUtilities.invokeLater.
        Auto-detect: if extra fields are empty and known string > 64 chars,
        the last 64 chars are treated as the extra field (e.g. token).
        """
        known = str(self._kfKnownArea.getText().strip())
        sep   = ""

        if not known:
            self._setKfResultStyled("Please enter the known concatenated string.")
            return

        pairs = self._kfReadParsedFields()
        if not pairs:
            self._setKfResultStyled("No fields found. Paste a body and click Parse Body first.")
            return

        # ---- Auto-detect trailing 64-char extra field ----
        _TOKEN_LEN = 64
        _auto_detect_note = ""
        if self._kfAdditionalPanel._rows:
            first_key = self._kfAdditionalPanel._rows[0][0].getText().strip()
            first_val = self._kfAdditionalPanel._rows[0][1].getText().strip()
            # Only auto-detect if the first row (token) has a key but NO value
            if first_key and not first_val and len(known) > _TOKEN_LEN:
                token_val = known[-_TOKEN_LEN:]
                pairs[first_key] = token_val
                _auto_detect_note = "[Auto-detect] %s : %s" % (first_key, token_val)
                # Populate the auto-detected token back to the UI row
                self._kfAdditionalPanel._rows[0][1].setText(token_val)


        self._kfResultArea.setText("Searching... (running in background)")

        _outer = self
        _pairs_snap = dict(pairs)
        _known_snap = known
        _sep_snap   = sep
        _note_snap  = _auto_detect_note

        import threading as _threading

        def _run():
            keys = list(_pairs_snap.keys())
            values = {k: str(v) for k, v in _pairs_snap.items()}
            matches = []
            total_visited = [0]

            def dfs(current_perm, remaining_keys, remaining_known):
                total_visited[0] += 1
                if len(matches) >= 100 or total_visited[0] >= 10000:
                    return
                if not remaining_known:
                    if current_perm:
                        matches.append(current_perm)
                    return
                for k in remaining_keys:
                    val = values[k]
                    if not val:
                        continue
                    if remaining_known.startswith(val):
                        next_keys = [x for x in remaining_keys if x != k]
                        dfs(current_perm + (k,), next_keys, remaining_known[len(val):])

            dfs((), keys, _known_snap)

            lines = []
            if _note_snap:
                lines.append(_note_snap)
                lines.append(u"\u2500" * 52)

            if not matches:
                lines += ["No match found.", ""]
                # Show which field values appear in the known string
                found_keys = [(k, v) for k, v in _pairs_snap.items() if v and str(v) in _known_snap]
                if found_keys:
                    lines.append("Values found in known string:")
                    for k, v in found_keys:
                        lines.append("  %s : %s" % (k, v))
                    lines.append("")
                # Find segments in the known string not covered by any field value
                remaining = _known_snap
                for _, v in found_keys:
                    remaining = remaining.replace(str(v), "\x00", 1)
                unknown_parts = [p for p in remaining.split("\x00") if p]
                if unknown_parts:
                    lines.append("Unknown segment(s) not from any field:")
                    for part in unknown_parts:
                        lines.append("  %s" % part)
            else:
                for i, perm in enumerate(matches, 1):
                    if len(matches) > 1:
                        lines.append("Match #%d:" % i)
                    lines.append("Key order : %s" % ", ".join(perm))
                    if i < len(matches):
                        lines.append("")
                if len(matches) >= 100 or total_visited[0] >= 10000:
                    lines.append("")
                    lines.append("(Note: search was capped at 100 matches to optimize performance)")

            result_text = "\n".join(lines)
            def _update_ui():
                _outer._setKfResultStyled(result_text)
                _outer._lastKfMatches = matches
                _outer._kfApplyBtn.setEnabled(bool(matches))
            SwingUtilities.invokeLater(_update_ui)

        t = _threading.Thread(target=_run)
        t.setDaemon(True)
        t.start()

    def _onApplyKfResult(self, event=None):
        """Apply the chosen Key Finder result to the main Hash tab's fields."""
        if not self._lastKfMatches:
            JOptionPane.showMessageDialog(self._panel, "No matches to apply. Please run Find Key Order first.", "Apply Result", JOptionPane.WARNING_MESSAGE)
            return

        selected_match = None
        if len(self._lastKfMatches) == 1:
            selected_match = self._lastKfMatches[0]
        else:
            options = [", ".join(m) for m in self._lastKfMatches]
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
            self._keysOrderField.setText(", ".join(selected_match))
            
            # Copy Key Finder's request body to Hash tab's payload area
            kf_body = self._kfBodyArea.getText()
            if kf_body:
                self._payloadArea.setText(kf_body)
            

            # 2. Merge Key Finder extra fields into Hash tab's custom data panel
            hash_pairs = self._customDataPanel.getPairs()
            kf_pairs = self._kfAdditionalPanel.getPairs()
            for k, v in kf_pairs.items():
                if k:
                    # ONLY add if the key exists in the selected key order result
                    if k in selected_match:
                        hash_pairs[k] = v
            self._customDataPanel.setPairs(hash_pairs)
            
            # 3. Switch view/focus to the Hash tab (index 0)
            self._tabbedPane.setSelectedIndex(0)
            
            # 4. Trigger rehash immediately with the newly applied fields
            try:
                self._shouldCompareHash = True
                self._onGenerate()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Actions: Crypto
    # -------------------------------------------------------------------------
    def _onCryptoRun(self, event=None):
        """Encrypt or decrypt using the selected crypto snippet algorithm."""
        try:
            algo      = str(self._cryptoAlgoCombo.getSelectedItem())
            mode      = str(self._cryptoModeCombo.getSelectedItem())
            key       = self._cryptoKeyField.getText()
            iv        = self._cryptoIvField.getText().strip()
            input_txt = self._cryptoInputArea.getText().strip()

            snippet = self.crypto_snippet_manager.get_snippet(algo)
            if not snippet:
                self._cryptoOutputArea.setText("Error: Algorithm '%s' not found." % algo)
                return

            needs_key = self.crypto_snippet_manager.requires_key(algo)
            if needs_key and not key:
                self._cryptoOutputArea.setText("Error: Key is required for %s." % algo)
                return
            if not input_txt:
                self._cryptoOutputArea.setText("Error: Input is empty.")
                return

            result = CryptoSnippetEngine.execute(snippet, mode, input_txt, key, iv)
            self._cryptoOutputArea.setText(str(result))

        except Exception as e:
            self._cryptoOutputArea.setText("Error: %s" % str(e))

    # -------------------------------------------------------------------------
    # Actions: Generator
    # -------------------------------------------------------------------------
    def _onGenerate(self, event=None):
        name = self._algoCombo.getSelectedItem()
        if not name:
            self._outputArea.setText("Error: No algorithm selected.")
            self._debugArea.setText("")
            if hasattr(self, '_mainStatusLabel'):
                self._mainStatusLabel.setText("")
            self._shouldCompareHash = False
            return

        snippet = self.snippet_manager.get_snippet(str(name))
        if not snippet:
            self._outputArea.setText("Error: Snippet '%s' not found." % name)
            self._debugArea.setText("")
            if hasattr(self, '_mainStatusLabel'):
                self._mainStatusLabel.setText("")
            self._shouldCompareHash = False
            return

        try:
            payload_str = self._payloadArea.getText().strip()

            payload = parse_body(payload_str, "")
            if not payload:
                self._outputArea.setText("Error: Payload could not be parsed or is empty.")
                self._debugArea.setText("")
                if hasattr(self, '_mainStatusLabel'):
                    self._mainStatusLabel.setText("")
                self._shouldCompareHash = False
                return
            passcode = self._passcodeField.getText()
            custom_data = self._customDataPanel.getPairs()

            keys_str = self._keysOrderField.getText().strip()
            key_order = None
            if keys_str:
                key_order = [k.strip() for k in keys_str.split(',') if k.strip()]

            result, debug_log = CryptoEngine.execute_snippet(
                snippet["code"], payload, passcode, custom_data, key_order
            )

            result_str = str(result)
            if not result_str.startswith("Error") and self._globalUppercaseHashChk.isSelected():
                result_str = result_str.upper()

            self._outputArea.setText(result_str)
            self._debugArea.setText(str(debug_log))

            # Status check against old hash in the body (only if triggered by apply)
            if hasattr(self, '_mainStatusLabel'):
                try:
                    if getattr(self, '_shouldCompareHash', False) and isinstance(payload, dict):
                        flat_payload = flatten_data(payload)
                        hash_key = self._mainHashFieldName.getText().strip() or "hash"
                        old_hash = flat_payload.get(hash_key)
                        if old_hash and not result_str.startswith("Error"):
                            old_h = str(old_hash).strip().lower()
                            new_h = str(result_str).strip().lower()
                            if old_h == new_h:
                                self._mainStatusLabel.setForeground(Color(0, 150, 0))  # Green
                                self._mainStatusLabel.setText("(Valid)")
                            else:
                                self._mainStatusLabel.setForeground(Color(200, 0, 0))  # Red
                                self._mainStatusLabel.setText("(Invalid)")
                        else:
                            self._mainStatusLabel.setText("")
                    else:
                        self._mainStatusLabel.setText("")
                except Exception:
                    self._mainStatusLabel.setText("")
                finally:
                    self._shouldCompareHash = False

        except Exception as e:
            if hasattr(self, '_mainStatusLabel'):
                self._mainStatusLabel.setText("")
            self._shouldCompareHash = False
            self._outputArea.setText("Error: %s" % str(e))
            self._debugArea.setText(traceback.format_exc())

    def _onGetTimestampGlobal(self, event=None):
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

    def _tryExtractKeys(self):
        """Auto-extract keys from payload using the selected body format."""
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            data = parse_body(payload_str, "")
            if isinstance(data, dict) and data:
                keys = [k for k in data.keys() if k != 'hash']
                new_keys_str = ", ".join(keys)
                current = self._keysOrderField.getText().strip()
                if current != new_keys_str:
                    self._keysOrderField.setText(new_keys_str)
        except:
            pass

    def _tryFormatJson(self):
        try:
            payload_str = self._payloadArea.getText().strip()
            if not payload_str:
                return
            data = json.loads(payload_str)
            formatted = json.dumps(data, indent=2)
            if formatted != payload_str:
                self._payloadArea.setText(formatted)
        except:
            pass

    # -------------------------------------------------------------------------
    # Actions: Settings Option Toggle & Tab Visibility
    # -------------------------------------------------------------------------
    def _load_settings(self):
        defaults = {
            "show_crypto": False,
            "show_app_setting": True,
            "show_batch_mapper": True,
            "show_get_timestamp": False,
            "show_run_hash": True,
            "default_app": "aba mobile"
        }
        try:
            if os.path.exists(self.settings_path):
                with open(self.settings_path, "r") as f:
                    loaded = json.load(f)
                    defaults.update(loaded)
                    if "show_crypto_v2" not in loaded:
                        defaults["show_crypto"] = False
                    return defaults
        except Exception as e:
            print("[CipherKit] Error loading settings: %s" % str(e))
        return defaults

    def _save_settings(self):
        try:
            with open(self.settings_path, "w") as f:
                json.dump(self.ext_settings, f, indent=2)
        except Exception as e:
            print("[CipherKit] Error saving settings: %s" % str(e))

    def _onSaveExtensionSettings(self, event=None):
        try:
            self.ext_settings["show_app_setting"] = self._optShowAs.isSelected()
            self.ext_settings["show_batch_mapper"] = self._optShowBatch.isSelected()
            self.ext_settings["show_crypto"] = self._optShowCrypto.isSelected()
            self.ext_settings["show_crypto_v2"] = True
            self.ext_settings["show_get_timestamp"] = self._optShowTsBtn.isSelected()
            self.ext_settings["show_run_hash"] = self._optShowRunHashBtn.isSelected()
            self.ext_settings["default_app"] = str(self._optDefaultAppCombo.getSelectedItem())
            
            self._save_settings()
            self.update_tab_visibility()
            # Apply a newly selected default app to already-open request editors.
            for tab in list(self._editor_tabs):
                try:
                    if getattr(tab, '_currentMessage', None) is not None:
                        tab._keysUserEdited = False
                        tab._tryLoadAppSetting()
                        tab._onGenerate()
                except Exception as refresh_error:
                    print("[CipherKit] Default app refresh error: %s" % str(refresh_error))
            JOptionPane.showMessageDialog(self._mainPanel, "Extension settings saved and updated successfully!", "Settings Saved", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self._mainPanel, "Error saving settings: %s" % str(e), "Error", JOptionPane.ERROR_MESSAGE)

    def update_tab_visibility(self):
        show_as = self.ext_settings.get("show_app_setting", True)
        show_batch = self.ext_settings.get("show_batch_mapper", True)
        
        # Re-add to suite tab if we want to change extender level tabs
        self._tabbedPane = JTabbedPane()
        if show_batch:
            self._tabbedPane.addTab("Batch Mapper", self._batchMapperPanel)
        if show_as:
            self._tabbedPane.addTab("AppSetting", self._settingPanel)
        self._tabbedPane.addTab("Extension Setting", self._extensionSettingPanel)

        # Clear and swap self._mainPanel center component
        self._mainPanel.removeAll()
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)
        self._mainPanel.revalidate()
        self._mainPanel.repaint()

        # Broadcast to all inline editor tabs
        alive_tabs = []
        for tab in self._editor_tabs:
            try:
                tab.update_tab_visibility()
                alive_tabs.append(tab)
            except Exception:
                pass
        self._editor_tabs = alive_tabs

    def show_main_app_setting(self, app_name=None):
        """Select the full AppSetting editor inside the CipherKit suite tab."""
        if not self.ext_settings.get("show_app_setting", True):
            raise ValueError("The main AppSetting tab is disabled in Extension Options.")
        self._refreshSettingCombo()
        if app_name and app_name != "(none)":
            self._settingCombo.setSelectedItem(app_name)
        self._refreshSettingSummary()
        self._tabbedPane.setSelectedComponent(self._settingPanel)
