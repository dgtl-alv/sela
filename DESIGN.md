---
version: alpha
name: ALVA Application System
description: Calm operational clarity with restrained ALVA teal accents.
colors:
  primary: "#007C78"
  primary-strong: "#005F5C"
  primary-soft: "#E2F5F3"
  ink: "#111111"
  muted: "#667085"
  surface: "#FFFFFF"
  canvas: "#F4F7F7"
  border: "#DFE5E7"
  success: "#16794A"
  success-soft: "#E5F6ED"
  warning: "#825700"
  warning-soft: "#FFF4D6"
typography:
  display:
    fontFamily: Inter
    fontSize: 3rem
    fontWeight: 700
    lineHeight: 1.08
    letterSpacing: "-0.035em"
  heading:
    fontFamily: Inter
    fontSize: 1.25rem
    fontWeight: 700
    lineHeight: 1.3
  body:
    fontFamily: Inter
    fontSize: 1rem
    fontWeight: 400
    lineHeight: 1.65
  label:
    fontFamily: Inter
    fontSize: 0.75rem
    fontWeight: 700
    lineHeight: 1.4
    letterSpacing: "0.1em"
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  2xl: 48px
rounded:
  sm: 8px
  md: 12px
  lg: 16px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.surface}"
    rounded: "{rounded.sm}"
    padding: 16px
  button-primary-hover:
    backgroundColor: "{colors.primary-strong}"
    textColor: "{colors.surface}"
    rounded: "{rounded.sm}"
    padding: 16px
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.sm}"
    padding: 16px
  navigation-active:
    backgroundColor: "{colors.primary-strong}"
    textColor: "{colors.surface}"
    rounded: "{rounded.sm}"
    padding: 12px
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.lg}"
    padding: 24px
  app-canvas:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.ink}"
  supporting-copy:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
  brand-tint:
    backgroundColor: "{colors.primary-soft}"
    textColor: "{colors.primary-strong}"
  status-success:
    backgroundColor: "{colors.success-soft}"
    textColor: "{colors.success}"
    rounded: "{rounded.lg}"
    padding: 8px
  status-warning:
    backgroundColor: "{colors.warning-soft}"
    textColor: "{colors.warning}"
    rounded: "{rounded.lg}"
    padding: 8px
  divider:
    backgroundColor: "{colors.border}"
    textColor: "{colors.ink}"
    height: 1px
---

## Overview

ALVA applications optimize operational clarity, not decoration. Use quiet surfaces, strong hierarchy, generous whitespace, and one restrained teal accent. Product workflows remain domain-specific while navigation, form behavior, feedback, and accessibility stay consistent.

## Colors

- **Primary:** Actions, focus, active navigation, and restrained brand emphasis.
- **Ink:** Main content and high-contrast labels.
- **Muted:** Supporting text only; never essential status by itself.
- **Canvas and surface:** Separate application background from work areas.
- **Success and warning:** Always pair color with text or icon meaning.

## Typography

Use Inter when available and the system sans-serif stack as fallback. Keep headings short. Use sentence case. Reserve uppercase and letter spacing for small eyebrow labels.

## Layout

Use the canonical sidebar, top bar, breadcrumb, page header, and content panel structure. Main content width is bounded. At widths below 760px, navigation becomes horizontal, metrics stack, and primary actions become full-width.

## Elevation & Depth

Use borders before shadows. Small shadows separate cards from canvas. Medium shadows are reserved for focused surfaces such as authentication panels and dialogs.

## Shapes

Use 8px for controls, 12px for compact containers, and 16px for major cards. Pills are reserved for status badges.

## Components

Buttons have a minimum 44px target. Tables live in labeled scroll regions on narrow screens. Every workflow provides loading, empty, validation, permission-denied, dependency-failure, and success states without relying on color alone.

## Do's and Don'ts

- Do reuse tokens from `internal/web/static/app.css`.
- Do preserve semantic landmarks, labels, focus visibility, and keyboard order.
- Do use one primary action per page section.
- Don't add raw hex colors or arbitrary spacing inside page templates.
- Don't hide authorization decisions in navigation visibility.
- Don't use color as the only status indicator.
