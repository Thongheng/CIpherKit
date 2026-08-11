# -*- coding: utf-8 -*-
from javax.swing import (
    JPanel, JLabel, JTextField, JButton, BoxLayout, Box
)
from javax.swing.border import EmptyBorder
from java.awt import (
    BorderLayout, Dimension, FlowLayout, Component
)
from ui.components.listeners import PayloadDocumentListener

class CustomDataPanel(JPanel):
    """
    A panel that holds one or more key:value custom data fields.
    Each row: [key_name] : [value] [+] [-]
    getPairs() returns a {key: value} dict of the entered custom data.
    """

    def __init__(self, label_font=None, field_font=None):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._label_font = label_font  # None = inherit LaF
        self._field_font = field_font  # None = inherit LaF
        self._rows = []  # list of (key_field, value_field)
        self._addFieldRow()

    def _addFieldRow(self, key="", value=""):
        row = JPanel(BorderLayout(4, 0))
        row.setMaximumSize(Dimension(9999, 30))
        row.setAlignmentX(Component.LEFT_ALIGNMENT)

        # Key field (narrower, fixed ~90px)
        keyField = JTextField(key)
        keyField.setPreferredSize(Dimension(90, 26))
        keyField.setToolTipText("Key name (use in Keys Order)")

        # Separator label
        sep = JLabel(":")
        sep.setBorder(EmptyBorder(0, 4, 0, 4))

        # Value field (stretches)
        valueField = JTextField(value)

        # Left part: key + colon + value
        kvPanel = JPanel(BorderLayout(0, 0))
        kvPanel.add(keyField, BorderLayout.WEST)
        kvPanel.add(sep, BorderLayout.CENTER)
        kvPanel.add(valueField, BorderLayout.EAST)
        # Make value field stretch with remaining space
        kvPanel2 = JPanel(BorderLayout(2, 0))
        kvPanel2.add(keyField, BorderLayout.WEST)
        kvPanel2.add(sep, BorderLayout.CENTER)
        kvPanel2.add(valueField, BorderLayout.CENTER)
        row.add(kvPanel2, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 2, 0))
        addBtn = JButton("+")
        addBtn.setPreferredSize(Dimension(32, 24))
        addBtn.setToolTipText("Add another custom data field")
        addBtn.addActionListener(lambda e: self._onAdd())
        btnPanel.add(addBtn)

        removeBtn = JButton("-")
        removeBtn.setPreferredSize(Dimension(32, 24))
        removeBtn.setToolTipText("Remove this field")
        removeBtn.addActionListener(lambda e, r=row, kf=keyField, vf=valueField: self._onRemove(r, kf, vf))
        btnPanel.add(removeBtn)

        row.add(btnPanel, BorderLayout.EAST)

        self._rows.append((keyField, valueField))
        self.add(row)
        self.add(Box.createVerticalStrut(3))
        self.revalidate()
        self.repaint()

    def _onAdd(self):
        self._addFieldRow()

    def _onRemove(self, row, keyField, valueField):
        if len(self._rows) <= 1:
            keyField.setText("")
            valueField.setText("")
            return
        # Improvement-4: find and remove the spacer that was added alongside this row
        idx = -1
        comps = list(self.getComponents())
        for i, c in enumerate(comps):
            if c is row:
                idx = i
                break
        self._rows.remove((keyField, valueField))
        self.remove(row)
        if idx >= 0 and idx < len(comps) - 1:
            nxt = comps[idx + 1]
            if isinstance(nxt, Box.Filler):
                self.remove(nxt)
        self.revalidate()
        self.repaint()

    def getPairs(self):
        """Return dict of {key: value} for all rows with a key name."""
        result = {}
        for kf, vf in self._rows:
            k = kf.getText().strip()
            v = vf.getText()
            if k:
                result[k] = v
        return result

    def setPairs(self, pairs):
        """Set rows from a dict {key: value}."""
        self.removeAll()
        self._rows = []
        if not pairs:
            self._addFieldRow()
            return
        for k, v in pairs.items():
            self._addFieldRow(str(k), str(v) if v else "")


# =============================================================================
# Compact Custom Data Panel for inline editor tab (narrower, key:value)
# =============================================================================
class CompactCustomDataPanel(JPanel):
    """Compact key:value custom data panel for the inline request editor tab."""

    def __init__(self, font=None, on_change=None):
        JPanel.__init__(self)
        self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
        self._font = font  # None = inherit default LaF font
        self._on_change = on_change  # called on direct user edits, NOT on setPairs()
        self._rows = []
        self._addFieldRow()

    def _fireChange(self):
        if self._on_change:
            self._on_change()

    def _addFieldRow(self, key="", value=""):
        row = JPanel(BorderLayout(2, 0))
        row.setMaximumSize(Dimension(9999, 24))
        row.setAlignmentX(Component.LEFT_ALIGNMENT)

        keyField = JTextField(key)
        keyField.setPreferredSize(Dimension(70, 20))
        keyField.setToolTipText("Key name (use in Keys Order)")
        if self._on_change:
            keyField.getDocument().addDocumentListener(PayloadDocumentListener(self._fireChange))

        sep = JLabel(":")
        sep.setBorder(EmptyBorder(0, 2, 0, 2))

        valueField = JTextField(value)
        if self._on_change:
            valueField.getDocument().addDocumentListener(PayloadDocumentListener(self._fireChange))

        # key | ":" in a fixed-width panel, value takes the rest
        keyWithSep = JPanel(BorderLayout(0, 0))
        keyWithSep.add(keyField, BorderLayout.CENTER)
        keyWithSep.add(sep, BorderLayout.EAST)
        keyWithSep.setPreferredSize(Dimension(80, 20))

        kvPanel = JPanel(BorderLayout(2, 0))
        kvPanel.add(keyWithSep, BorderLayout.WEST)
        kvPanel.add(valueField, BorderLayout.CENTER)
        row.add(kvPanel, BorderLayout.CENTER)

        btnPanel = JPanel(FlowLayout(FlowLayout.RIGHT, 1, 0))
        addBtn = JButton("+")
        addBtn.setPreferredSize(Dimension(26, 20))
        addBtn.addActionListener(lambda e: self._onAdd())
        btnPanel.add(addBtn)

        removeBtn = JButton("-")
        removeBtn.setPreferredSize(Dimension(26, 20))
        removeBtn.addActionListener(lambda e, r=row, kf=keyField, vf=valueField: self._onRemove(r, kf, vf))
        btnPanel.add(removeBtn)

        row.add(btnPanel, BorderLayout.EAST)

        self._rows.append((keyField, valueField))
        self.add(row)
        self.add(Box.createVerticalStrut(2))
        self.revalidate()
        self.repaint()

    def _onAdd(self):
        self._addFieldRow()

    def _onRemove(self, row, keyField, valueField):
        if len(self._rows) <= 1:
            keyField.setText("")
            valueField.setText("")
            return
        # Improvement-4: track and remove paired spacer
        idx = -1
        comps = list(self.getComponents())
        for i, c in enumerate(comps):
            if c is row:
                idx = i
                break
        self._rows.remove((keyField, valueField))
        self.remove(row)
        if idx >= 0 and idx < len(comps) - 1:
            nxt = comps[idx + 1]
            if isinstance(nxt, Box.Filler):
                self.remove(nxt)
        self.revalidate()
        self.repaint()
        self._fireChange()

    def getPairs(self):
        result = {}
        for kf, vf in self._rows:
            k = kf.getText().strip()
            v = vf.getText()
            if k:
                result[k] = v
        return result

    def getKeys(self):
        return [kf.getText().strip() for kf, vf in self._rows if kf.getText().strip()]

    def setPairs(self, pairs):
        self.removeAll()
        self._rows = []
        if not pairs:
            self._addFieldRow()
            return
        for k, v in pairs.items():
            self._addFieldRow(str(k), str(v) if v else "")



# =============================================================================
# UI Helper: Focus listener for auto-formatting JSON
