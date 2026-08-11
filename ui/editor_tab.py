# -*- coding: utf-8 -*-
from __future__ import print_function
import json, time, traceback
from javax.swing import (
    JPanel, JLabel, JTextField, JTextArea, JTextPane, JButton, JComboBox, JCheckBox,
    JScrollPane, JTabbedPane, JSplitPane, JOptionPane
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
from core.hasher import compute_hash
from core.key_finder import (
    compare_generated_hash, format_hash_comparison,
    should_render_hash_output, strip_hash_comparison,
    fetch_all_frida_candidates, extract_gap_value,
)
from ui.components.rounded_border import RoundedBorder
from ui.components.custom_data_panel import CompactCustomDataPanel
from ui.components.listeners import PayloadDocumentListener

class HashGenEditorTab(IMessageEditorTab):
    """
    Appears as a tab alongside Pretty/Raw/Hex in the request viewer.
    Sign Order and Custom Data are edited here; the hash is always
    recomputed and re-injected automatically — there is no manual
    "run"/"add" step.
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
        self._shouldCompareHash = False

        # Fonts
        monoFont  = Font("Monospaced", Font.PLAIN, 12)

        # ---- Root panel ----
        self._panel = JPanel(BorderLayout(3, 3))
        self._panel.setBorder(EmptyBorder(4, 4, 4, 4))

        # ================================================================
        # TOP: Unified Control Header Panel (No sub-tabs)
        # ================================================================
        headerPanel = JPanel(GridBagLayout())
        headerPanel.setBorder(EmptyBorder(2, 4, 4, 4))

        hgbc = GridBagConstraints()
        hgbc.insets = Insets(2, 3, 2, 3)
        hgbc.fill = GridBagConstraints.HORIZONTAL
        hgbc.weightx = 1.0

        self._customDataPanel = CompactCustomDataPanel(on_change=self._onCustomDataManualEdit)
        self._keysField = JTextField()
        self._keysField.getDocument().addDocumentListener(
            PayloadDocumentListener(self._onKeysManualEdit)
        )
        self._hashFieldName = JTextField("hash")
        self._hashFieldName.setToolTipText("JSON key name where the output will be injected")

        # Profile Match Status Indicator
        self._inlineSettingStatus = JLabel("No profile matched")
        self._inlineSettingStatus.setFont(Font("SansSerif", Font.PLAIN, 11))
        self._inlineSettingStatus.setForeground(Color(100, 100, 100))

        # Row 0: Sign Order [ textfield ] + [ Save Endpoint ] button
        hgbc.gridy = 0; hgbc.gridx = 0; hgbc.weightx = 0.0; hgbc.fill = GridBagConstraints.NONE; hgbc.anchor = GridBagConstraints.WEST
        headerPanel.add(JLabel("Sign Order:"), hgbc)

        signOrderRow = JPanel(BorderLayout(4, 0))
        signOrderRow.add(self._keysField, BorderLayout.CENTER)
        saveEpBtn = JButton("Save Endpoint", actionPerformed=self._onInlineSaveSetting)
        saveEpBtn.setToolTipText("Save current URL path + Sign Order under ABA Mobile")
        signOrderRow.add(saveEpBtn, BorderLayout.EAST)

        hgbc.gridx = 1; hgbc.gridwidth = 3; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        headerPanel.add(signOrderRow, hgbc)
        hgbc.gridwidth = 1  # restore

        # Row 1: Custom Data [ key-values ] + [ Apply ] button
        hgbc.gridy = 1; hgbc.gridx = 0; hgbc.weightx = 0.0; hgbc.fill = GridBagConstraints.NORTHWEST
        headerPanel.add(JLabel("Custom Data:"), hgbc)

        customDataRow = JPanel(BorderLayout(6, 0))
        customDataRow.add(self._customDataPanel, BorderLayout.CENTER)

        doApplyBtn = JButton("Apply to All Endpoints", actionPerformed=self._onInlineApplyCustomValue)
        doApplyBtn.setToolTipText("Overwrite these custom data values across every saved ABA Mobile endpoint")
        customDataRow.add(doApplyBtn, BorderLayout.EAST)

        hgbc.gridx = 1; hgbc.gridwidth = 3; hgbc.weightx = 1.0; hgbc.fill = GridBagConstraints.HORIZONTAL
        headerPanel.add(customDataRow, hgbc)
        hgbc.gridwidth = 1  # restore

        # Row 2: status line (profile match / Frida-recovered token / hash mismatch context)
        hgbc.gridy = 2; hgbc.gridx = 0; hgbc.gridwidth = 4; hgbc.weightx = 1.0; hgbc.weighty = 0.0
        hgbc.fill = GridBagConstraints.HORIZONTAL; hgbc.anchor = GridBagConstraints.WEST

        actionRow = JPanel(BorderLayout(6, 0))
        actionRow.add(self._inlineSettingStatus, BorderLayout.WEST)
        headerPanel.add(actionRow, hgbc)
        hgbc.gridwidth = 1  # restore

        self._headerPanel = headerPanel
        self._panel.add(headerPanel, BorderLayout.NORTH)

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
        self._outputTabs.addTab("Frida Log", kfOutputScroll)
        outputWrap.add(self._outputTabs, BorderLayout.CENTER)

        # ---- Debounce timer for auto-hash on body/Sign-Order/Custom-Data changes ----
        _outerRef2 = self
        self._pendingSyncFrida = False
        class _AutoHashAction(ActionListener):
            def actionPerformed(self, e):
                try:
                    sync = _outerRef2._pendingSyncFrida
                    _outerRef2._pendingSyncFrida = False
                    _outerRef2._onAnyFieldChanged(sync_frida=sync)
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
                    _outerRef2._scheduleAutoHash(sync_frida=True)
        self._bodyArea.getDocument().addDocumentListener(_BodyDocListener())
        self._bodyLoadingProgrammatically = False

        hcSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, bodyWrap, outputWrap)
        hcSplit.setResizeWeight(0.92)
        hashCryptoCard.add(hcSplit, BorderLayout.CENTER)

        self._panel.add(hashCryptoCard, BorderLayout.CENTER)

        # Sync config fields from the main tab if available
        self._syncFromMainTab()

    def _syncFromMainTab(self):
        """Copy config values from the main HashGen tab to this inline tab if available."""
        try:
            ext = self._extender
            if hasattr(ext, '_customDataPanel'):
                main_pairs = ext._customDataPanel.getPairs()
                if any(main_pairs.values()):
                    self._customDataPanel.setPairs(main_pairs)
            if hasattr(ext, '_keysOrderField') and not self._keysUserEdited:
                mainKeys = ext._keysOrderField.getText().strip()
                if mainKeys:
                    self._setKeysField(mainKeys, False)
        except Exception:
            pass

    def _applyAppSettingToInlineUI(self, app, ep=None):
        """Apply app-level setting config + optional endpoint to all inline UI fields."""
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
        if ep and "keys_order" in ep:
            self._setKeysField(ep["keys_order"], False, app=app, ep=ep)
        else:
            self._syncCustomDataForSignOrder(app=app, ep=ep)

    def _tryLoadAppSetting(self):
        """Auto-load ABA Mobile endpoint settings matching current URL path.
        Returns True if a setting was loaded, False otherwise."""
        try:
            path = getattr(self, '_requestPath', '')
            default_name = "ABA Mobile"
            app_name, app, pattern, ep = (
                self._extender.app_setting_manager.resolve_for_url(path, default_name)
            )

            if not app:
                if hasattr(self, '_inlineSettingStatus'):
                    self._inlineSettingStatus.setText("No profile matched")
                    self._inlineSettingStatus.setForeground(Color(160, 100, 0))
                return False

            self._applyAppSettingToInlineUI(app, ep)
            try:
                if hasattr(self, '_inlineSettingStatus'):
                    if ep and pattern:
                        self._inlineSettingStatus.setText("Matched: ABA Mobile / %s" % pattern)
                        self._inlineSettingStatus.setForeground(Color(0, 140, 0))
                    else:
                        self._inlineSettingStatus.setText("Default ABA Mobile profile (%s)" % (path or "/"))
                        self._inlineSettingStatus.setForeground(Color(70, 70, 70))
            except Exception:
                pass
            print("[CipherKit] Loaded app setting: ABA Mobile / %s" % (pattern or "(default)"))
            return True
        except Exception as e:
            print("[CipherKit] AppSetting load error: %s" % str(e))
            return False

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
        """Mark that the user has manually edited the keys order field and refresh hash."""
        if not self._keysLoadingProgrammatically:
            self._keysUserEdited = True
            self._syncCustomDataForSignOrder()
            self._onFieldParamChange()

    def _onFieldParamChange(self):
        """Re-evaluate hash generation and output comparison when config fields change."""
        if not getattr(self, '_keysLoadingProgrammatically', False):
            self._scheduleAutoHash(sync_frida=True)

    def _onCustomDataManualEdit(self):
        """User edited Custom Data directly (e.g. pasted a token by hand) — just
        recompute/inject; don't re-run the Frida lookup and overwrite their edit."""
        self._scheduleAutoHash(sync_frida=False)

    def _scheduleAutoHash(self, sync_frida):
        """Debounce rapid edits (typing in the body, Sign Order, or Custom Data)
        into a single recompute+inject 600ms after the last keystroke."""
        if sync_frida:
            self._pendingSyncFrida = True
        self._setHashStatus("")
        self._autoHashTimer.restart()

    def _onAnyFieldChanged(self, sync_frida=True):
        """Recompute and inject the hash, immediately. Backfills any Sign-Order
        key not present in the body (the secret token) from the Frida log for
        this request's ts first, when sync_frida is set."""
        if sync_frida:
            self._syncTokenFromFridaLog()
        self._shouldCompareHash = True
        self._onGenerateAndInject()

    def _setKeysField(self, value, user_edited=False, app=None, ep=None):
        """Update Sign Order without firing the manual-edit state accidentally."""
        self._keysLoadingProgrammatically = True
        try:
            self._keysField.setText(value or "")
            self._syncCustomDataForSignOrder(app=app, ep=ep)
        finally:
            self._keysLoadingProgrammatically = False
            self._keysUserEdited = bool(user_edited)

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

    def _syncTokenFromFridaLog(self):
        """Look up this request's ts in the Frida log and fill any Sign-Order key
        that isn't already present in the body (the secret token) with the value
        recovered from that log entry. Deterministic \u2014 no brute-force search,
        since Sign Order is already known once the endpoint's profile is saved.
        Overwrites the existing custom-data value: a different ts is a genuinely
        different real request with its own correct token, so there's no
        ambiguity to preserve."""
        try:
            body = self._bodyArea.getText().strip()
            if not body:
                return

            ct = getattr(self, '_contentType', '')
            payload = parse_body(body, ct)
            body_values = flatten_data(payload) if isinstance(payload, dict) else {}

            sign_keys = [k.strip() for k in self._keysField.getText().strip().split(",") if k.strip()]
            if not sign_keys:
                return

            ignore_keys = set(["hash", "signature", "sign", "sig", "mac"])
            gap_keys = [k for k in sign_keys if k not in body_values and k.lower() not in ignore_keys]
            if not gap_keys:
                return  # every signed field is already in the body \u2014 nothing to look up
            gap_key = gap_keys[0]

            ts_val = (body_values.get('ts') or body_values.get('timestamp')
                      or body_values.get('time') or body_values.get('req_time'))
            if not ts_val:
                return

            candidates = fetch_all_frida_candidates(ts_val=ts_val, values=body_values)
            if not candidates:
                self._setKfResultStyled("No Frida log entry for ts=%s" % ts_val)
                return

            raw_string = candidates[0][0]
            gap_value = extract_gap_value(body_values, raw_string, sign_keys, gap_key)
            if gap_value is None:
                self._setKfResultStyled(
                    "Frida log entry found for ts=%s, but Sign Order doesn't reconstruct it" % ts_val
                )
                return

            current_pairs = self._customDataPanel.getPairs()
            current_pairs[gap_key] = gap_value
            self._customDataPanel.setPairs(current_pairs)
            self._setKfResultStyled("%s recovered from Frida log (ts=%s)" % (gap_key, ts_val))
        except Exception as e:
            print("[CipherKit] Frida token lookup error: %s" % str(e))

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

    def update_tab_visibility(self):
        pass

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
        return bool(isRequest)

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

            # Backfill any Sign-Order key not present in the body (the secret
            # token) from the Frida log for this request's ts — always, since
            # each loaded request carries its own ts and its own correct entry.
            self._syncTokenFromFridaLog()

            try:
                self._onGenerate()
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
        """Save current endpoint keys order under ABA Mobile."""
        path = getattr(self, '_requestPath', '')
        app_name = "ABA Mobile"

        pattern = JOptionPane.showInputDialog(
            self._panel, "URL pattern for this endpoint (e.g. /api/v3/my_endpoint):",
            "URL Pattern", JOptionPane.PLAIN_MESSAGE, None, None, path
        )
        if not pattern or not str(pattern).strip():
            return
        pattern = str(pattern).strip()

        try:
            keys_order = self._keysField.getText().strip()
        except Exception:
            keys_order = ""

        resolved_custom_data = self._customDataPanel.getPairs()

        app_data = {
            "algorithm":   "SHA-1",
            "custom_data": resolved_custom_data,
            "hash_field":  self._hashFieldName.getText().strip() or "hash",
        }
        self._extender.app_setting_manager.save_app(app_name, app_data)
        self._extender.app_setting_manager.save_endpoint(app_name, pattern, keys_order, resolved_custom_data)

        try:
            self._extender._refreshSettingSummary()
        except:
            pass
        label = u"ABA Mobile — %s" % pattern
        try:
            if hasattr(self, '_inlineSettingStatus'):
                self._inlineSettingStatus.setText(u"✓ Saved: %s" % label)
                self._inlineSettingStatus.setForeground(Color(0, 140, 0))
        except Exception:
            pass
        self._hashOutput.setText("Saved: %s" % label)
        print("[CipherKit] AppSetting endpoint saved: %s" % label)



    def _onInlineApplyCustomValue(self, event=None):
        """Bulk-update all custom data key-values entered in _customDataPanel across ABA Mobile settings."""
        name = "ABA Mobile"
        mgr = self._extender.app_setting_manager
        app = mgr.get_app(name)
        if not app:
            JOptionPane.showMessageDialog(self._panel, "ABA Mobile configuration not found.",
                                          "Apply Custom Data", JOptionPane.ERROR_MESSAGE)
            return

        pairs = self._customDataPanel.getPairs()
        if not pairs:
            return

        shared = app.get("custom_data", {})
        for k, v in pairs.items():
            shared[k] = v

        count = 0
        for pat, ep in app.get("endpoints", {}).items():
            ep_custom = ep.setdefault("custom_data", {})
            for k, v in pairs.items():
                if k in ep_custom or k in shared:
                    ep_custom[k] = v
                    count += 1

        mgr.save()

        try:
            self._onGenerate()
        except Exception:
            pass

        try:
            self._extender._refreshSettingSummary()
        except Exception:
            pass

        try:
            if hasattr(self, '_inlineSettingStatus'):
                self._inlineSettingStatus.setText(u"✓ Custom Data applied across ABA Mobile settings")
                self._inlineSettingStatus.setForeground(Color(0, 140, 0))
        except Exception:
            pass

    def _computeHash(self):
        try:
            body_str = self._bodyArea.getText().strip()
            ct = getattr(self, '_contentType', '')
            payload = parse_body(body_str, ct)
            if not payload:
                return "Error: Body could not be parsed or is empty.", ""

            custom_data = self._customDataPanel.getPairs()
            keys_str = self._keysField.getText().strip()
            digest, raw_string, debug_log = compute_hash(payload, keys_str, custom_data)
            self._lastRawString = raw_string
            return str(digest), debug_log
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
