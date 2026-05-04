# -*- coding: utf-8 -*-
#
# Burp Extension: Copy Sanitized HTTP Request (headers + params, 4 modes)
#
# Features:
# - Context menu (right-click on HTTP message):
#   1) Copy request (headers sanitized)
#   2) Copy request (headers/params redacted)
#   3) Copy request (headers/params masked)
#   4) Copy request (all features)
#
# - "Copy Sanitized Request" tab with 2 sub-tabs:
#   * Headers:
#       - list of headers to REMOVE
#       - list of headers to REDACT   (value -> redact placeholder)
#       - list of headers to MASK     (value -> mask placeholder)
#   * Parameters:
#       - list of parameter names to REDACT (URL + body)
#       - list of parameter names to MASK   (URL + body)
#       - separate redact / mask placeholders
#       - toggle: Include JSON format copying (pretty-print JSON bodies)
#
# Notes:
# - Parameter processing supports:
#   * URL query string
#   * application/x-www-form-urlencoded bodies
#   * application/json bodies (best-effort, key-based, preserves key order)
#   (best-effort; other formats like multipart are left as is for safety)


from burp import IBurpExtender, IContextMenuFactory, ITab

from javax.swing import (
    JPanel, JLabel, JTextArea, JTextField, JButton,
    JScrollPane, BoxLayout, JMenuItem, JTabbedPane, JCheckBox
)
from javax.swing.border import EmptyBorder
from javax.swing.event import DocumentListener

from java.awt import BorderLayout, Dimension, FlowLayout, Toolkit, Color
from java.awt.datatransfer import StringSelection

import re
import json
from collections import OrderedDict


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab):

    MODE_HEADERS_ONLY = 1
    MODE_REDACT = 2
    MODE_MASK = 3
    MODE_ALL = 4

    #
    # IBurpExtender
    #
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RequestRedactorX")

        # ---------- Defaults ----------

        # Headers to remove completely
        self._default_blacklist = [
            "accept",
            "accept-encoding",
            "accept-language",
            "if-modified-since",
            "if-none-match",
            "priority",
            "sec-ch-ua",
            "sec-ch-ua-arch",
            "sec-ch-ua-bitness",
            "sec-ch-ua-full-version",
            "sec-ch-ua-mobile",
            "sec-ch-ua-model",
            "sec-ch-ua-platform",
            "sec-ch-ua-platform-version",
            "sec-ch-ua-wow64",
            "sec-fetch-dest",
            "sec-fetch-mode",
            "sec-fetch-site",
            "sec-fetch-user",
            "upgrade-insecure-requests",
            "x-requested-with",
        ]

        # Headers to redact / mask by default
        self._default_redact_headers = [
            "cookie",
            "cookies",
            "authorization",
        ]
        self._default_mask_headers = []

        # Parameters to redact / mask by default
        self._default_param_redact = []
        self._default_param_mask = []

        # Placeholders (headers)
        self._default_redact_placeholder = "[REDACTED]"
        self._default_mask_placeholder = "[...]"

        # Placeholders (params)
        self._default_param_redact_placeholder = "[REDACTED]"
        self._default_param_mask_placeholder = "[...]"

        # Settings keys
        self._setting_blacklist = "csr_blacklist_headers"
        self._setting_redact_headers = "csr_redact_headers"
        self._setting_mask_headers = "csr_mask_headers"
        self._setting_redact_placeholder = "csr_redact_placeholder"
        self._setting_mask_placeholder = "csr_mask_placeholder"

        self._setting_param_redact = "csr_param_redact"
        self._setting_param_mask = "csr_param_mask"
        self._setting_param_redact_placeholder = "csr_param_redact_placeholder"
        self._setting_param_mask_placeholder = "csr_param_mask_placeholder"

        # New: JSON formatting toggle
        self._setting_pretty_json = "csr_pretty_json"

        # Load settings / init state
        self._load_settings()

        # Register context menu factory
        callbacks.registerContextMenuFactory(self)

        # Build UI tab
        self._build_ui()
        callbacks.addSuiteTab(self)

        print("[+] RequestRedactorX: loaded")

    # ---------- Settings ----------

    def _load_settings(self):
        # Headers blacklist
        stored_blacklist = self._callbacks.loadExtensionSetting(self._setting_blacklist)
        if stored_blacklist:
            headers = [h.strip().lower() for h in stored_blacklist.splitlines() if h.strip()]
            self._blacklist = set(headers)
        else:
            self._blacklist = set(self._default_blacklist)

        # Headers to redact
        stored_redact = self._callbacks.loadExtensionSetting(self._setting_redact_headers)
        if stored_redact:
            headers = [h.strip().lower() for h in stored_redact.splitlines() if h.strip()]
            self._redact_headers = set(headers)
        else:
            self._redact_headers = set(self._default_redact_headers)

        # Headers to mask
        stored_mask = self._callbacks.loadExtensionSetting(self._setting_mask_headers)
        if stored_mask:
            headers = [h.strip().lower() for h in stored_mask.splitlines() if h.strip()]
            self._mask_headers = set(headers)
        else:
            self._mask_headers = set(self._default_mask_headers)

        # Header placeholders
        stored_redact_placeholder = self._callbacks.loadExtensionSetting(self._setting_redact_placeholder)
        self._redact_placeholder = (
            stored_redact_placeholder.strip()
            if stored_redact_placeholder and stored_redact_placeholder.strip()
            else self._default_redact_placeholder
        )

        stored_mask_placeholder = self._callbacks.loadExtensionSetting(self._setting_mask_placeholder)
        self._mask_placeholder = (
            stored_mask_placeholder.strip()
            if stored_mask_placeholder and stored_mask_placeholder.strip()
            else self._default_mask_placeholder
        )

        # Parameter names to redact
        stored_param_redact = self._callbacks.loadExtensionSetting(self._setting_param_redact)
        if stored_param_redact:
            names = [p.strip().lower() for p in stored_param_redact.splitlines() if p.strip()]
            self._param_redact_names = set(names)
        else:
            self._param_redact_names = set(self._default_param_redact)

        # Parameter names to mask
        stored_param_mask = self._callbacks.loadExtensionSetting(self._setting_param_mask)
        if stored_param_mask:
            names = [p.strip().lower() for p in stored_param_mask.splitlines() if p.strip()]
            self._param_mask_names = set(names)
        else:
            self._param_mask_names = set(self._default_param_mask)

        # Parameter placeholders
        stored_param_redact_placeholder = self._callbacks.loadExtensionSetting(self._setting_param_redact_placeholder)
        self._param_redact_placeholder = (
            stored_param_redact_placeholder.strip()
            if stored_param_redact_placeholder and stored_param_redact_placeholder.strip()
            else self._default_param_redact_placeholder
        )

        stored_param_mask_placeholder = self._callbacks.loadExtensionSetting(self._setting_param_mask_placeholder)
        self._param_mask_placeholder = (
            stored_param_mask_placeholder.strip()
            if stored_param_mask_placeholder and stored_param_mask_placeholder.strip()
            else self._default_param_mask_placeholder
        )

        # JSON pretty-print toggle (default: True)
        stored_pretty_json = self._callbacks.loadExtensionSetting(self._setting_pretty_json)
        if stored_pretty_json is None or stored_pretty_json.strip() == "" or stored_pretty_json.lower() == "true":
            self._pretty_json_enabled = True
        else:
            self._pretty_json_enabled = False

    def _save_settings(self):
        # Serialize lists to line-separated strings
        blacklist_text = "\n".join(sorted(self._blacklist))
        redact_text = "\n".join(sorted(self._redact_headers))
        mask_text = "\n".join(sorted(self._mask_headers))

        param_redact_text = "\n".join(sorted(self._param_redact_names))
        param_mask_text = "\n".join(sorted(self._param_mask_names))

        self._callbacks.saveExtensionSetting(self._setting_blacklist, blacklist_text)
        self._callbacks.saveExtensionSetting(self._setting_redact_headers, redact_text)
        self._callbacks.saveExtensionSetting(self._setting_mask_headers, mask_text)
        self._callbacks.saveExtensionSetting(self._setting_redact_placeholder, self._redact_placeholder)
        self._callbacks.saveExtensionSetting(self._setting_mask_placeholder, self._mask_placeholder)

        self._callbacks.saveExtensionSetting(self._setting_param_redact, param_redact_text)
        self._callbacks.saveExtensionSetting(self._setting_param_mask, param_mask_text)
        self._callbacks.saveExtensionSetting(
            self._setting_param_redact_placeholder, self._param_redact_placeholder
        )
        self._callbacks.saveExtensionSetting(
            self._setting_param_mask_placeholder, self._param_mask_placeholder
        )

        # Save JSON pretty-print toggle
        self._callbacks.saveExtensionSetting(
            self._setting_pretty_json,
            "true" if self._pretty_json_enabled else "false"
        )

        print("[+] RequestRedactorX: settings saved")

    # ---------- UI (ITab) ----------

    def _build_ui(self):
        main_panel = JPanel(BorderLayout())
        tabs = JTabbedPane()

        # Status labels (one per tab; both updated together)
        self._status_labels = []

        headers_tab = self._build_headers_tab()
        params_tab = self._build_params_tab()

        tabs.addTab("Headers", headers_tab)
        tabs.addTab("Parameters", params_tab)

        main_panel.add(tabs, BorderLayout.CENTER)
        main_panel.setPreferredSize(Dimension(700, 520))

        self._main_panel = main_panel

    def _make_status_label(self):
        label = JLabel(" ")
        label.setForeground(Color.GRAY)
        self._status_labels.append(label)
        return label

    def _set_status(self, text, color):
        for label in self._status_labels:
            label.setText(text)
            label.setForeground(color)

    def _mark_dirty(self):
        self._set_status(u"● Unsaved changes", Color(0xCC, 0x66, 0x00))

    def _mark_saved(self):
        self._set_status(u"✓ Settings saved", Color(0x00, 0x88, 0x00))

    def _attach_dirty_listener(self, text_component):
        ext = self

        class _DirtyListener(DocumentListener):
            def insertUpdate(self, e):
                ext._mark_dirty()

            def removeUpdate(self, e):
                ext._mark_dirty()

            def changedUpdate(self, e):
                ext._mark_dirty()

        text_component.getDocument().addDocumentListener(_DirtyListener())

    def _build_headers_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Headers to remove
        remove_panel = JPanel(BorderLayout(5, 5))
        remove_panel.setBorder(EmptyBorder(0, 0, 10, 0))
        lbl_remove = JLabel("Headers to REMOVE completely (one per line, case-insensitive):")
        remove_panel.add(lbl_remove, BorderLayout.NORTH)

        self._headers_textarea = JTextArea()
        self._headers_textarea.setLineWrap(True)
        self._headers_textarea.setWrapStyleWord(True)
        self._headers_textarea.setText("\n".join(sorted(self._blacklist)))
        scroll_remove = JScrollPane(self._headers_textarea)
        scroll_remove.setPreferredSize(Dimension(640, 110))
        remove_panel.add(scroll_remove, BorderLayout.CENTER)
        panel.add(remove_panel)

        # Headers to redact
        redact_panel = JPanel()
        redact_panel.setLayout(BoxLayout(redact_panel, BoxLayout.Y_AXIS))
        redact_panel.setBorder(EmptyBorder(0, 0, 10, 0))

        lbl_redact_headers = JLabel(
            "Headers to REDACT (value replaced by redact placeholder):"
        )
        redact_panel.add(lbl_redact_headers)

        self._redact_headers_textarea = JTextArea()
        self._redact_headers_textarea.setLineWrap(True)
        self._redact_headers_textarea.setWrapStyleWord(True)
        self._redact_headers_textarea.setText("\n".join(sorted(self._redact_headers)))
        scroll_redact = JScrollPane(self._redact_headers_textarea)
        scroll_redact.setPreferredSize(Dimension(640, 80))
        redact_panel.add(scroll_redact)

        lbl_redact_placeholder = JLabel("Redact placeholder (e.g. [REDACTED]):")
        redact_panel.add(lbl_redact_placeholder)

        self._redact_placeholder_field = JTextField()
        self._redact_placeholder_field.setText(self._redact_placeholder)
        self._redact_placeholder_field.setMaximumSize(Dimension(640, 26))
        redact_panel.add(self._redact_placeholder_field)

        panel.add(redact_panel)

        # Headers to mask
        mask_panel = JPanel()
        mask_panel.setLayout(BoxLayout(mask_panel, BoxLayout.Y_AXIS))
        mask_panel.setBorder(EmptyBorder(0, 0, 10, 0))

        lbl_mask_headers = JLabel("Headers to MASK (value replaced by mask placeholder):")
        mask_panel.add(lbl_mask_headers)

        self._mask_headers_textarea = JTextArea()
        self._mask_headers_textarea.setLineWrap(True)
        self._mask_headers_textarea.setWrapStyleWord(True)
        self._mask_headers_textarea.setText("\n".join(sorted(self._mask_headers)))
        scroll_mask = JScrollPane(self._mask_headers_textarea)
        scroll_mask.setPreferredSize(Dimension(640, 80))
        mask_panel.add(scroll_mask)

        lbl_mask_placeholder = JLabel("Mask placeholder (e.g. [...], *****, [MASKED]):")
        mask_panel.add(lbl_mask_placeholder)

        self._mask_placeholder_field = JTextField()
        self._mask_placeholder_field.setText(self._mask_placeholder)
        self._mask_placeholder_field.setMaximumSize(Dimension(640, 26))
        mask_panel.add(self._mask_placeholder_field)

        panel.add(mask_panel)

        # Attach dirty listeners
        self._attach_dirty_listener(self._headers_textarea)
        self._attach_dirty_listener(self._redact_headers_textarea)
        self._attach_dirty_listener(self._mask_headers_textarea)
        self._attach_dirty_listener(self._redact_placeholder_field)
        self._attach_dirty_listener(self._mask_placeholder_field)

        # Save button + status label
        buttons_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_save = JButton("Save settings", actionPerformed=self._on_save_clicked)
        buttons_panel.add(btn_save)
        buttons_panel.add(self._make_status_label())
        panel.add(buttons_panel)

        return panel

    def _build_params_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(EmptyBorder(10, 10, 10, 10))

        # Param names to redact
        redact_panel = JPanel()
        redact_panel.setLayout(BoxLayout(redact_panel, BoxLayout.Y_AXIS))
        redact_panel.setBorder(EmptyBorder(0, 0, 10, 0))

        lbl_param_redact = JLabel(
            "Parameter names to REDACT (URL query + x-www-form-urlencoded body + JSON keys):"
        )
        redact_panel.add(lbl_param_redact)

        self._param_redact_textarea = JTextArea()
        self._param_redact_textarea.setLineWrap(True)
        self._param_redact_textarea.setWrapStyleWord(True)
        self._param_redact_textarea.setText("\n".join(sorted(self._param_redact_names)))
        scroll_param_redact = JScrollPane(self._param_redact_textarea)
        scroll_param_redact.setPreferredSize(Dimension(640, 80))
        redact_panel.add(scroll_param_redact)

        lbl_param_redact_placeholder = JLabel("Parameter redact placeholder (e.g. [REDACTED]):")
        redact_panel.add(lbl_param_redact_placeholder)

        self._param_redact_placeholder_field = JTextField()
        self._param_redact_placeholder_field.setText(self._param_redact_placeholder)
        self._param_redact_placeholder_field.setMaximumSize(Dimension(640, 26))
        redact_panel.add(self._param_redact_placeholder_field)

        panel.add(redact_panel)

        # Param names to mask
        mask_panel = JPanel()
        mask_panel.setLayout(BoxLayout(mask_panel, BoxLayout.Y_AXIS))
        mask_panel.setBorder(EmptyBorder(0, 0, 10, 0))

        lbl_param_mask = JLabel(
            "Parameter names to MASK (URL query + x-www-form-urlencoded body + JSON keys):"
        )
        mask_panel.add(lbl_param_mask)

        self._param_mask_textarea = JTextArea()
        self._param_mask_textarea.setLineWrap(True)
        self._param_mask_textarea.setWrapStyleWord(True)
        self._param_mask_textarea.setText("\n".join(sorted(self._param_mask_names)))
        scroll_param_mask = JScrollPane(self._param_mask_textarea)
        scroll_param_mask.setPreferredSize(Dimension(640, 80))
        mask_panel.add(scroll_param_mask)

        lbl_param_mask_placeholder = JLabel(
            "Parameter mask placeholder (e.g. [...], *****, [MASKED]):"
        )
        mask_panel.add(lbl_param_mask_placeholder)

        self._param_mask_placeholder_field = JTextField()
        self._param_mask_placeholder_field.setText(self._param_mask_placeholder)
        self._param_mask_placeholder_field.setMaximumSize(Dimension(640, 26))
        mask_panel.add(self._param_mask_placeholder_field)

        panel.add(mask_panel)

        # JSON format toggle
        json_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        self._json_format_checkbox = JCheckBox(
            "Include JSON format copying (pretty-print application/json bodies)",
            self._pretty_json_enabled
        )
        json_panel.add(self._json_format_checkbox)
        panel.add(json_panel)

        # Attach dirty listeners
        self._attach_dirty_listener(self._param_redact_textarea)
        self._attach_dirty_listener(self._param_mask_textarea)
        self._attach_dirty_listener(self._param_redact_placeholder_field)
        self._attach_dirty_listener(self._param_mask_placeholder_field)
        self._json_format_checkbox.addItemListener(
            lambda e: self._mark_dirty()
        )

        # Save button (same handler as headers tab) + status label
        buttons_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_save = JButton("Save settings", actionPerformed=self._on_save_clicked)
        buttons_panel.add(btn_save)
        buttons_panel.add(self._make_status_label())
        panel.add(buttons_panel)

        return panel

    def _on_save_clicked(self, event):
        # Headers: blacklist
        txt_blacklist = self._headers_textarea.getText()
        self._blacklist = set(
            [h.strip().lower() for h in txt_blacklist.splitlines() if h.strip()]
        )

        # Headers: redact
        txt_redact = self._redact_headers_textarea.getText()
        self._redact_headers = set(
            [h.strip().lower() for h in txt_redact.splitlines() if h.strip()]
        )

        # Headers: mask
        txt_mask = self._mask_headers_textarea.getText()
        self._mask_headers = set(
            [h.strip().lower() for h in txt_mask.splitlines() if h.strip()]
        )

        # Header placeholders
        rp = self._redact_placeholder_field.getText()
        mp = self._mask_placeholder_field.getText()
        self._redact_placeholder = (
            rp.strip() if rp and rp.strip() else self._default_redact_placeholder
        )
        self._mask_placeholder = (
            mp.strip() if mp and mp.strip() else self._default_mask_placeholder
        )

        # Params: redact names
        txt_param_redact = self._param_redact_textarea.getText()
        self._param_redact_names = set(
            [p.strip().lower() for p in txt_param_redact.splitlines() if p.strip()]
        )

        # Params: mask names
        txt_param_mask = self._param_mask_textarea.getText()
        self._param_mask_names = set(
            [p.strip().lower() for p in txt_param_mask.splitlines() if p.strip()]
        )

        # Param placeholders
        prp = self._param_redact_placeholder_field.getText()
        pmp = self._param_mask_placeholder_field.getText()
        self._param_redact_placeholder = (
            prp.strip() if prp and prp.strip() else self._default_param_redact_placeholder
        )
        self._param_mask_placeholder = (
            pmp.strip() if pmp and pmp.strip() else self._default_param_mask_placeholder
        )

        # JSON pretty-print toggle
        if hasattr(self, "_json_format_checkbox"):
            self._pretty_json_enabled = self._json_format_checkbox.isSelected()

        self._save_settings()
        self._mark_saved()

    # ---------- ITab ----------

    def getTabCaption(self):
        return "RequestRedactorX"

    def getUiComponent(self):
        return self._main_panel

    # ---------- IContextMenuFactory ----------

    def createMenuItems(self, invocation):
        try:
            messages = invocation.getSelectedMessages()
        except Exception as e:
            print("[!] Error getting selected messages: %s" % e)
            return None

        if not messages or len(messages) == 0:
            return None

        msg = messages[0]
        items = []

        # 1) Headers only
        item1 = JMenuItem("Copy request (headers sanitized)")

        def action1(event):
            try:
                self.copy_sanitized_request(msg, self.MODE_HEADERS_ONLY)
            except Exception as e:
                print("[!] Error (mode 1): %s" % e)

        item1.addActionListener(action1)
        items.append(item1)

        # 2) Redact (headers + params)
        item2 = JMenuItem("Copy request (headers/params redacted)")

        def action2(event):
            try:
                self.copy_sanitized_request(msg, self.MODE_REDACT)
            except Exception as e:
                print("[!] Error (mode 2): %s" % e)

        item2.addActionListener(action2)
        items.append(item2)

        # 3) Mask (headers + params)
        item3 = JMenuItem("Copy request (headers/params masked)")

        def action3(event):
            try:
                self.copy_sanitized_request(msg, self.MODE_MASK)
            except Exception as e:
                print("[!] Error (mode 3): %s" % e)

        item3.addActionListener(action3)
        items.append(item3)

        # 4) All features
        item4 = JMenuItem("Copy request (sanitize + redact + mask)")

        def action4(event):
            try:
                self.copy_sanitized_request(msg, self.MODE_ALL)
            except Exception as e:
                print("[!] Error (mode 4): %s" % e)

        item4.addActionListener(action4)
        items.append(item4)

        return items

    # ---------- Core sanitization logic ----------

    def copy_sanitized_request(self, message_info, mode):
        request_bytes = message_info.getRequest()
        if request_bytes is None:
            return

        request_info = self._helpers.analyzeRequest(message_info)
        headers = list(request_info.getHeaders())
        body_offset = request_info.getBodyOffset()
        body_bytes = request_bytes[body_offset:]
        body_str = self._helpers.bytesToString(body_bytes)

        if not headers:
            return

        # Detect content-type (for body handling)
        content_type = None
        for h in headers[1:]:
            h_lower = h.lower()
            if h_lower.startswith("content-type:"):
                try:
                    content_type = h.split(":", 1)[1].strip().lower()
                except:
                    content_type = None
                break

        # Sanitize request line (URL params)
        request_line = headers[0]
        parts = request_line.split(" ")
        if len(parts) == 3:
            method, path_query, proto = parts
            path_query_sanitized = self._sanitize_query_in_path(path_query, mode)
            sanitized_headers = ["%s %s %s" % (method, path_query_sanitized, proto)]
        else:
            # if something odd, keep as is
            sanitized_headers = [request_line]

        # Sanitize headers
        for h in headers[1:]:
            parts = h.split(":", 1)
            if len(parts) != 2:
                sanitized_headers.append(h)
                continue

            name_raw = parts[0].strip()
            name = name_raw.lower()
            value = parts[1].lstrip()

            # 1) remove blacklisted headers
            if name in self._blacklist:
                continue

            # 2) redact / mask depending on mode
            if mode in (self.MODE_REDACT, self.MODE_ALL) and name in self._redact_headers:
                sanitized_headers.append(self._redact_header(name_raw, name, value))
                continue

            if mode in (self.MODE_MASK, self.MODE_ALL) and name in self._mask_headers:
                sanitized_headers.append(self._mask_header(name_raw, name, value))
                continue

            # 3) leave as is
            sanitized_headers.append(h)

        # Sanitize body parameters (if applicable)
        if mode == self.MODE_HEADERS_ONLY:
            body_out = body_str
        else:
            body_out = self._sanitize_body_params(body_str, mode, content_type)

        sanitized_request = "\r\n".join(sanitized_headers) + "\r\n\r\n" + body_out

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(sanitized_request)
        clipboard.setContents(selection, selection)

        print("[+] Copied request (mode %d) to clipboard" % mode)

    # ---------- Header helpers ----------

    def _redact_header(self, name_raw, name, value):
        # Special handling for Authorization: keep scheme
        if name == "authorization":
            val_stripped = value.strip()
            parts = val_stripped.split(" ", 1)
            if len(parts) == 2:
                scheme = parts[0]
                new_val = scheme + " " + self._redact_placeholder
            else:
                new_val = self._redact_placeholder
            return name_raw + ": " + new_val

        return name_raw + ": " + self._redact_placeholder

    def _mask_header(self, name_raw, name, value):
        if name == "authorization":
            val_stripped = value.strip()
            parts = val_stripped.split(" ", 1)
            if len(parts) == 2:
                scheme = parts[0]
                new_val = scheme + " " + self._mask_placeholder
            else:
                new_val = self._mask_placeholder
            return name_raw + ": " + new_val

        return name_raw + ": " + self._mask_placeholder

    # ---------- Parameter helpers (URL + body) ----------

    def _sanitize_query_in_path(self, path_query, mode):
        # path_query is like "/path?param1=val1&param2=val2"
        if "?" not in path_query:
            return path_query

        path, query = path_query.split("?", 1)
        query_sanitized = self._sanitize_query_string(query, mode)
        return path + "?" + query_sanitized

    def _sanitize_query_string(self, query, mode):
        if not query or ("=" not in query):
            return query

        parts = query.split("&")
        new_parts = []

        for part in parts:
            if "=" not in part:
                new_parts.append(part)
                continue

            key, val = part.split("=", 1)
            lname = key.strip().lower()
            new_val = val

            if lname:
                if mode in (self.MODE_REDACT, self.MODE_ALL) and lname in self._param_redact_names:
                    new_val = self._param_redact_placeholder
                elif mode in (self.MODE_MASK, self.MODE_ALL) and lname in self._param_mask_names:
                    new_val = self._param_mask_placeholder

            new_parts.append("%s=%s" % (key, new_val))

        return "&".join(new_parts)

    def _sanitize_body_params(self, body, mode, content_type):
        """
        Decide how to sanitize the body based on content-type.
        - application/x-www-form-urlencoded -> treat as query string
        - application/json -> parse and sanitize JSON keys (preserve order, optional pretty-print)
        - others -> left unchanged for safety
        """
        if not body:
            return body

        if not content_type:
            # If no content-type, best-effort for query-like body
            if "=" in body and "&" in body:
                return self._sanitize_query_string(body, mode)
            return body

        # JSON bodies (application/json, possibly with charset, etc.)
        if "application/json" in content_type:
            return self._sanitize_json_body(body, mode)

        # Classic form-encoded
        if "application/x-www-form-urlencoded" in content_type:
            return self._sanitize_query_string(body, mode)

        # For now: do not try to modify other content-types (multipart, XML, etc.)
        return body

    def _sanitize_json_body(self, body, mode):
        """
        Best-effort JSON sanitizer.
        - Parses body as JSON using OrderedDict to preserve key order
        - Walks dicts/lists recursively
        - If a key matches param-redact / param-mask lists (case-insensitive),
          its value is replaced with the appropriate placeholder.
        - If JSON format copying is enabled, returns pretty-printed JSON (jq-style: 2-space indent).
          Otherwise returns compact JSON (no extra formatting).
        If parsing fails, the original body is returned unchanged.
        """
        try:
            parsed = json.loads(body.strip(), object_pairs_hook=OrderedDict)
        except Exception:
            # If it's not valid JSON, do not touch it
            return body

        def walk(value):
            if isinstance(value, dict) or isinstance(value, OrderedDict):
                new_obj = OrderedDict()
                for k, v in value.items():
                    lname = k.strip().lower()
                    if lname and mode in (self.MODE_REDACT, self.MODE_ALL) and lname in self._param_redact_names:
                        new_obj[k] = self._param_redact_placeholder
                    elif lname and mode in (self.MODE_MASK, self.MODE_ALL) and lname in self._param_mask_names:
                        new_obj[k] = self._param_mask_placeholder
                    else:
                        new_obj[k] = walk(v)
                return new_obj
            elif isinstance(value, list):
                return [walk(item) for item in value]
            else:
                # Primitive (string, number, bool, null) – leave as is
                return value

        sanitized = walk(parsed)

        try:
            if self._pretty_json_enabled:
                # Pretty JSON, key order preserved, no key sorting
                return json.dumps(sanitized, indent=2, separators=(",", ": "))
            else:
                # Compact JSON, key order preserved
                return json.dumps(sanitized, separators=(",", ":"))
        except Exception:
            # In case of serialization issues, fall back to original
            return body