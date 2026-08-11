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
from core.app_setting_manager import AppSettingManager, mask_secret, merge_custom_data
from core.body_parser import parse_body, serialize_body, flatten_data
from core.hasher import compute_hash
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
        snippets_path     = os.path.join(script_dir, "snippets.json")
        app_settings_path = os.path.join(script_dir, "app_settings.json")
        self.snippet_manager     = SnippetManager(snippets_path)
        self.app_setting_manager = AppSettingManager(app_settings_path)
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

            custom_data = merge_custom_data(
                app.get("custom_data"), ep.get("custom_data") if ep else None
            )
            keys_order_str = ep.get("keys_order", "") if ep else ""
            hash_field = app.get("hash_field", "hash")
            algorithm = app.get("algorithm", "SHA-1")

            digest, raw_string, _ = compute_hash(payload, keys_order_str, custom_data, algorithm=algorithm)

            # Inject the new hash back into the body
            payload[hash_field] = digest
            new_body = serialize_body(payload, body_str, content_type)
            new_body_bytes = self._helpers.stringToBytes(new_body)
            new_request = self._helpers.buildHttpMessage(headers, new_body_bytes)
            currentRequest.setRequest(new_request)

            print("[CipherKit] Auto-Rehash: app_setting='%s' pattern='%s' hash_field='%s' value='%s'" % (
                app_name, pattern, hash_field, digest[:40]
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

        self._generatorPanel   = self._buildGeneratorTab()   # initialises shared fields
        self._buildKeyFinderTab()                            # initialises shared KF fields
        self._batchMapperPanel = BatchMapperTab(self)
        self._settingPanel     = self._buildSettingTab()

        self._tabbedPane = JTabbedPane()
        self._tabbedPane.addTab("Batch Mapper", self._batchMapperPanel)
        self._tabbedPane.addTab("AppSetting (ABA Mobile)", self._settingPanel)

        self._mainPanel.removeAll()
        self._mainPanel.add(self._tabbedPane, BorderLayout.CENTER)

    # -------------------------------------------------------------------------
    # AppSetting Tab (ABA Mobile Dashboard)
    # -------------------------------------------------------------------------
    def _buildSettingTab(self):
        mainPanel = JPanel(BorderLayout(0, 8))
        mainPanel.setBorder(EmptyBorder(10, 10, 10, 10))

        self._settingSummaryArea = JTextArea()
        self._settingSummaryArea.setEditable(False)
        self._settingSummaryArea.setFont(Font("Monospaced", Font.PLAIN, 12))
        self._settingSummaryArea.setBorder(EmptyBorder(5, 5, 5, 5))
        mainPanel.add(JScrollPane(self._settingSummaryArea), BorderLayout.CENTER)

        self._refreshSettingSummary()
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

        self._customDataPanel = CustomDataPanel()
        self._keysOrderField = JTextField()
        self._mainHashFieldName = JTextField("hash")
        self._mainHashFieldName.setToolTipText("JSON key name where the output will be injected")
        self._generateBtn = JButton("Generate", actionPerformed=self._onGenerate)

        # Row 0: Sign Order (spans columns 1-3)
        tgbc.gridy = 0
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE
        topPanel.add(JLabel("Sign Order:"), tgbc)
        tgbc.gridx = 1; tgbc.gridwidth = 3; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL
        topPanel.add(self._keysOrderField, tgbc)
        tgbc.gridwidth = 1  # restore

        # Row 1: Custom Data (spans columns 1-3)
        tgbc.gridy = 1
        tgbc.gridx = 0; tgbc.weightx = 0; tgbc.fill = GridBagConstraints.NONE; tgbc.anchor = GridBagConstraints.NORTHWEST
        topPanel.add(JLabel("Custom Data:"), tgbc)
        tgbc.gridx = 1; tgbc.gridwidth = 3; tgbc.weightx = 1.0; tgbc.fill = GridBagConstraints.HORIZONTAL; tgbc.anchor = GridBagConstraints.WEST
        topPanel.add(self._customDataPanel, tgbc)
        tgbc.gridwidth = 1  # restore

        # Row 2: Buttons (spans columns 0-3)
        tgbc.gridy = 2
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

    def _updatePasscodeFieldState(self):
        """No-op state updater since SHA-1 requires no secret key."""
        pass

    # -------------------------------------------------------------------------
    # AppSetting Actions (ABA Mobile Dashboard)
    # -------------------------------------------------------------------------
    def _refreshSettingSummary(self):
        """Refresh the AppSetting tab summary text area with ABA Mobile's config."""
        try:
            name = "ABA Mobile"
            app = self.app_setting_manager.get_app(name)
            if not app:
                self._settingSummaryArea.setText("(ABA Mobile setting not found)")
                return
            lines = []
            lines.append("App Setting : %s" % name)
            lines.append("")
            lines.append("Shared Config")
            lines.append("-" * 44)
            lines.append("  Algorithm     : SHA-1")
            lines.append("  Hash Field    : %s" % app.get("hash_field", "hash"))
            lines.append("  Default KF Key: %s" % app.get("default_kf_key", "token"))
            custom_data = app.get("custom_data", {})
            if custom_data:
                custom_str = ", ".join("%s=%s" % (k, v) for k, v in custom_data.items())
                lines.append("  Custom Data   : %s" % custom_str)
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

    def show_main_app_setting(self, app_name=None):
        """Switch the main suite tab to the AppSetting summary and refresh it."""
        try:
            self._refreshSettingSummary()
            if hasattr(self, '_tabbedPane') and hasattr(self, '_settingPanel'):
                idx = self._tabbedPane.indexOfComponent(self._settingPanel)
                if idx >= 0:
                    self._tabbedPane.setSelectedIndex(idx)
        except Exception as e:
            print("[CipherKit] show_main_app_setting error: %s" % str(e))

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
    # Actions: Generator
    # -------------------------------------------------------------------------
    def _onGenerate(self, event=None):
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

            custom_data = self._customDataPanel.getPairs()
            keys_str = self._keysOrderField.getText().strip()
            digest, raw_string, debug_log = compute_hash(payload, keys_str, custom_data)
            result_str = str(digest)

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

    def update_tab_visibility(self):
        alive_tabs = []
        for tab in self._editor_tabs:
            try:
                tab.update_tab_visibility()
                alive_tabs.append(tab)
            except Exception:
                pass
        self._editor_tabs = alive_tabs
