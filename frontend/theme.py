"""CyberShield Design System & Theme Definitions.

Follows Reference 3 (Threat Analytics) with a premium dark SOC interface.
Provides palette constants, typography hierarchies, and ttk style initializers.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# =============================================================================
# Color Palette - Reference 3 (Dark SOC Threat Analytics)
# =============================================================================
BG_DARK = "#090A11"            # Deep charcoal application background
BG_SIDEBAR = "#10121B"         # Layered charcoal navigation surface
BG_SIDEBAR_ACTIVE = "#221D35"  # Violet-tinted active navigation surface
BG_SIDEBAR_HOVER = "#191824"   # Soft elevated navigation surface
BG_CARD = "#171923"            # Smoky glass card surface
BG_CARD_HOVER = "#222330"      # Raised charcoal-violet surface
BG_INPUT = "#11131C"           # Recessed fields and search surface
BG_TOPBAR = "#11131B"           # Separate chrome layer above page content
BORDER_SUBTLE = "#2B2D3A"      # Quiet charcoal dividers
BORDER_GLASS = "#363442"       # Soft violet-charcoal glass edge
BORDER_FOCUS = "#8B68F6"       # Focused inputs and borders (primary accent)

# Accent Colors
ACCENT_PRIMARY = "#7545F5"     # Primary purple accent
ACCENT_SECONDARY = "#A855F7"   # Secondary light purple
ACCENT_HOVER = "#8A5CF6"       # Button hover purple
ACCENT_MUTED = "#2A1F4D"       # Subtle purple tint for badges

# Semantic Status Colors
COLOR_SUCCESS = "#22C55E"      # Success / online / resolved
COLOR_WARNING = "#F59E0B"      # Warning / caution / medium severity
COLOR_DANGER = "#EF4444"       # Danger / critical severity / offline
COLOR_INFO = "#3B82F6"         # Informational / low severity
COLOR_OFFLINE = "#94A3B8"      # Inactive / disconnected

# Text Colors
TEXT_PRIMARY = "#FFFFFF"       # Headings, active values, high contrast
TEXT_SECONDARY = "#CBD5E1"     # Standard readable body text
TEXT_MUTED = "#94A3B8"         # Labels, subtext, captions
TEXT_DIMMED = "#64748B"        # Disabled elements, placeholders

# =============================================================================
# Typography Definitions
# =============================================================================
FONT_FAMILY = "Segoe UI"
FONT_MONO = "Consolas"

FONT_TITLE = (FONT_FAMILY, 16, "bold")
FONT_SUBTITLE = (FONT_FAMILY, 12, "bold")
FONT_METRIC = (FONT_FAMILY, 22, "bold")
FONT_SECTION_HEADER = (FONT_FAMILY, 11, "bold")
FONT_BODY = (FONT_FAMILY, 10)
FONT_BODY_BOLD = (FONT_FAMILY, 10, "bold")
FONT_CAPTION = (FONT_FAMILY, 9)
FONT_CAPTION_BOLD = (FONT_FAMILY, 9, "bold")
FONT_BADGE = (FONT_FAMILY, 8, "bold")
FONT_BUTTON = (FONT_FAMILY, 10, "bold")
FONT_MONO_SMALL = (FONT_MONO, 9)


def apply_theme(root: tk.Tk | tk.Toplevel) -> ttk.Style:
    """Configure ttk widgets to seamlessly match the dark SOC design system.

    Args:
        root: The root Tk or Toplevel window.

    Returns:
        ttk.Style: The configured ttk Style object.
    """
    root.configure(bg=BG_DARK)
    style = ttk.Style(root)

    # Use clam or default engine for clean color overrides across platforms
    available_themes = style.theme_names()
    if "clam" in available_themes:
        style.theme_use("clam")

    # Treeview (Data Table) Styling
    style.configure(
        "Treeview",
        background=BG_CARD,
        foreground=TEXT_SECONDARY,
        fieldbackground=BG_CARD,
        borderwidth=0,
        bordercolor=BORDER_GLASS,
        lightcolor=BORDER_GLASS,
        darkcolor=BORDER_GLASS,
        relief="flat",
        font=FONT_BODY,
        rowheight=32,
    )
    style.configure(
        "Treeview.Heading",
        background=BG_INPUT,
        foreground=TEXT_MUTED,
        borderwidth=0,
        font=FONT_CAPTION_BOLD,
        relief="flat",
    )
    style.map(
        "Treeview.Heading",
        background=[("active", BORDER_SUBTLE)],
        foreground=[("active", TEXT_PRIMARY)],
    )
    style.map(
        "Treeview",
        background=[("selected", BG_SIDEBAR_ACTIVE)],
        foreground=[("selected", TEXT_PRIMARY)],
    )

    # Scrollbar Styling
    style.configure(
        "Vertical.TScrollbar",
        background=BG_INPUT,
        troughcolor=BG_DARK,
        borderwidth=0,
        arrowsize=12,
        relief="flat",
    )
    style.map(
        "Vertical.TScrollbar",
        background=[("active", BORDER_SUBTLE)],
    )

    # Entry Styling
    style.configure(
        "Dark.TEntry",
        fieldbackground=BG_INPUT,
        foreground=TEXT_PRIMARY,
        borderwidth=1,
        relief="flat",
        font=FONT_BODY,
        insertcolor=TEXT_PRIMARY,
    )

    return style

