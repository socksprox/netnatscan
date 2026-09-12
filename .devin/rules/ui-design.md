---
description: "UI design system for netnatscan — TDesign-styled component library shared with SFYGameTransferrer"
trigger: always_on
---

# UI Design Rules

This app's UI reuses the component library and design language from
`/Users/tamino/Code/N3DS/SFYGameTransferrer` (TDesign-styled Flutter).
**Do not invent new visual patterns** — reuse or extend the shared components.

**Do NOT add the `tdesign_flutter` package.** The slice of its API the
components need (`TDText`, `TDTheme`, `TDToast`, `TDFont`) is re-implemented
locally in `lib/widgets/tdesign.dart` — extend that file when a component
needs another piece of the API.

## Component library (already in `lib/`)

| Component | File | Use for |
| --- | --- | --- |
| `CustomAppBar` | `lib/widgets/custom_app_bar.dart` | Every screen's app bar (white/grey-900 surface, bottom border, soft shadow, `TDText` title) |
| `CenteredButton` | `lib/widgets/centered_button.dart` | All buttons (`isPrimary` = theme color, 40px height, radius 8) |
| `SquircleInput` | `lib/widgets/squircle_input.dart` | All text inputs (40px height, radius 8, bordered) |
| `TDesignTabSelector` | `lib/widgets/theme_tab_selector.dart` | Segmented pickers (animated sliding indicator in theme color) |
| `InfoDialog` | `lib/widgets/info_dialog.dart` | Alerts/confirmations (`InfoDialog.show(...)`) |
| `ThemeManager` | `lib/services/theme_manager.dart` | Singleton: light/dark/system mode + accent color, persisted |

## Design tokens

- **Dark-adaptive colors**: always derive from `Theme.of(context).brightness`.
  Surfaces: `white` / `grey.shade900`; cards: `white` / `grey.shade800`;
  borders: `grey.shade200` / `grey.shade800`; secondary text:
  `grey.shade600` / `grey.shade400`.
- **Radii**: 8 for inputs/buttons, 10–12 for cards/dialogs.
- **Shadows**: subtle `BoxShadow(color: black.withValues(alpha: isDark ? 0.2-0.3 : 0.03-0.05), offset: (0,1-2), blurRadius: 3-8)`.
- **Typography**: `TDText` with `TDTheme.of(context).fontTitleLarge/fontTitleMedium/fontBodyMedium/fontBodySmall`, `fontWeight: FontWeight.w600` for titles/values.
- **Accent**: never hardcode — use `ThemeManager().themeColor` (default `0xFF0052D9`).
- **Toasts**: `TDToast.showSuccess/showFail/showText(msg, context: context)`.
- **Icons**: Material icons, ~20–24px; icon-in-tinted-rounded-square pattern for list items (icon container: `blue.shade50` light / `blue.shade900.withValues(alpha: 0.3)` dark, radius 8).
- **Tap targets**: `Material` + `InkWell` with `borderRadius: 8`, padding 8.
- **Bottom nav**: `BottomNavigationBar` wrapped in `Theme` with splash/highlight/hover transparent, `type: fixed`, `enableFeedback: false`, outlined→filled icon swap.

## Layout patterns

- Screen body: `Padding(all: 16)`, `Column(crossAxisAlignment: stretch)`.
- List items: rounded card containers (`radius 10`, thin border, tiny shadow),
  `horizontal 12 / vertical 10` padding, icon tile + title/subtitle column +
  trailing action.
- Empty states: centered icon (`grey.shade300`/`700`, size 32) + title +
  hint line.
- Page structure: `Scaffold(appBar: CustomAppBar(...), body: IndexedStack(...), bottomNavigationBar: ...)`.

## Rules

- Keep it simple — this is a clean utility app, not a dashboard. One job per
  screen, generous whitespace, no clutter.
- New components must follow the tokens above and live in `lib/widgets/`.
- Do NOT add UI dependencies beyond `tdesign_flutter` + `flutter_colorpicker`
  without need.
