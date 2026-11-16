---
name: Cloister
description: A members-only private ZK rollup on QoreChain, drawn as a filed carbonless batch record.
colors:
  form-ink: "#22205c"
  stamp-violet: "#4b3fb4"
  canary-copy: "#ede06a"
  canary-deep: "#d9c84a"
  original-white: "#f4f1e8"
  redaction-black: "#141414"
  ribbon-black: "#1d1c1a"
  printed-rule: "rgba(34, 32, 92, 0.55)"
typography:
  display:
    fontFamily: "Archivo, sans-serif"
    fontSize: "186px"
    fontWeight: 900
    lineHeight: 0.8
    letterSpacing: "-0.03em"
    fontVariation: "'wdth' 125"
  headline:
    fontFamily: "Archivo, sans-serif"
    fontSize: "34px"
    fontWeight: 900
    letterSpacing: "0.02em"
    fontVariation: "'wdth' 70"
  title:
    fontFamily: "Archivo, sans-serif"
    fontSize: "27px"
    fontWeight: 700
    letterSpacing: "0.08em"
    fontVariation: "'wdth' 70"
  label:
    fontFamily: "Archivo, sans-serif"
    fontSize: "26px"
    fontWeight: 700
    letterSpacing: "0.09em"
    fontVariation: "'wdth' 70"
  body:
    fontFamily: "Courier Prime, monospace"
    fontSize: "36px"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "0.01em"
  body-sm:
    fontFamily: "Courier Prime, monospace"
    fontSize: "31px"
    fontWeight: 700
    lineHeight: 1.12
    letterSpacing: "0.01em"
  stamp:
    fontFamily: "Archivo, sans-serif"
    fontSize: "72px"
    fontWeight: 900
    lineHeight: 0.9
    letterSpacing: "0.02em"
    fontVariation: "'wdth' 100"
  stamp-caption:
    fontFamily: "Archivo, sans-serif"
    fontSize: "22px"
    fontWeight: 800
    letterSpacing: "0.16em"
    fontVariation: "'wdth' 80"
rounded:
  none: "0px"
  sprocket: "50%"
spacing:
  bar-gap: "12px"
  cell-x: "18px"
  cell-y: "12px"
  form-x: "56px"
  form-top: "46px"
  form-bottom: "40px"
  feed-column: "72px"
  sprocket: "22px"
  redaction-bar: "38px"
components:
  form-sheet:
    backgroundColor: "{colors.canary-copy}"
    textColor: "{colors.form-ink}"
    rounded: "{rounded.none}"
    padding: "46px 56px 40px"
  field-cell:
    backgroundColor: "{colors.canary-copy}"
    textColor: "{colors.form-ink}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "12px 18px 14px"
  typed-entry:
    textColor: "{colors.ribbon-black}"
    typography: "{typography.body}"
  redaction-bar:
    backgroundColor: "{colors.redaction-black}"
    rounded: "{rounded.none}"
    height: "38px"
  verified-stamp:
    textColor: "{colors.stamp-violet}"
    typography: "{typography.stamp}"
    rounded: "{rounded.none}"
    padding: "10px 26px 8px"
  sprocket-hole:
    backgroundColor: "{colors.form-ink}"
    rounded: "{rounded.sprocket}"
    size: "22px"
---

# Design System: Cloister

<!-- Recorded from the shipped cover (brand/cover.html, rendered brand/cover.png, 1920x1080). The build is ground truth. This file lives in brand/ on purpose: the repo-root design.md is the team's build plan, not this visual system. -->

## Overview

**Creative North Star: "The Redacted Record"**

Cloister is a filed batch settlement record: a carbonless multi-part office form whose structure is public, whose contents are blacked out, and whose verdict is rubber-stamped on top. Every surface is a sheet of paper in a form set: a canary public copy lying over a white original, printed in a single deep blue-violet ink, punched with tractor-feed sprocket margins, filled in on a typewriter, and redacted with solid black bars where Cloister actually hides data.

The world is flat, front-on and bureaucratic on purpose. It refuses the category default for crypto and ZK projects (a dark banner, a glowing lattice, gradient meshes, neon nodes). Its authority comes from the conventions of paperwork that everyone already knows how to read: labels are printed, entries are typed, secrets are struck out, verdicts are stamped. Density is high and orderly, like a real form; nothing floats.

The honesty principle is visual, not just verbal. What is readable on the sheet is exactly what the public can see on chain; what is redacted is exactly what Cloister seals to members. The sheet is always the *public copy*.

**Key Characteristics:**
- Carbonless form set: canary copy on top, white original offset beneath, deep ink field around.
- One printed ink (blue-violet) for every rule, label and title; typewriter black for entries; true black for redaction; violet for the stamp.
- Condensed printed labels (Archivo, narrow width axis) over typewritten values (Courier Prime bold).
- Solid redaction bars sized like the text they hide.
- A single flat violet VERIFIED stamp, double-ringed, struck at an angle.
- Square corners everywhere; the only circles are sprocket holes.

## Colors

A printed-paper palette: two paper stocks, one form ink, one stamp ink, two blacks, all flat.

### Primary
- **Form Ink Blue-Violet** (form-ink): the printed ink of the form. Wordmark, every label, every field rule, the header underline, sprocket holes, and the field around the sheet set. It is the identity color; when Cloister needs one color, it is this one.

### Secondary
- **Rubber-Stamp Violet** (stamp-violet): reserved for the VERIFIED stamp, the verdict mark. It is a brighter, separate ink from the form ink so the stamp reads as applied after printing.

### Neutral
- **Canary Copy** (canary-copy): the top sheet, part 2 of a carbonless set. The default surface for any Cloister page that shows a record.
- **Canary Shadow** (canary-deep): the darker canary for a sheet edge or the underside of a copy when a second canary tone is needed. Defined in the build but not yet visible on the cover; use sparingly.
- **Original White** (original-white): the white original peeking past the copy's edge, with its own printed rules. A secondary paper, never the main surface of a record.
- **Redaction Black** (redaction-black): solid redaction bars only.
- **Typewriter Ribbon** (ribbon-black): typed entries. Warm near-black, distinct from the redaction black so typed facts and struck-out secrets never read as the same mark.
- **Printed Rule** (printed-rule): form ink at 55% for secondary printed rules: the dashed tractor-feed perforations and the original sheet's field rules.

### Named Rules
**The One Ink Rule.** Everything printed on the form (title, labels, grid lines, rules) is form ink. Do not introduce a second print color.

**The Stamp Ink Is Earned Rule.** Stamp violet appears only on a verdict mark that the system can back (VERIFIED, settled by proof). It is never used for decoration, links or emphasis.

## Typography

**Display Font:** Archivo variable (wdth 62–125%, wght 100–900), with sans-serif fallback
**Body Font:** Courier Prime 700 (400 available), with monospace fallback
**Label Font:** Archivo at a narrow width (wdth 70%)

**Character:** Archivo is the form's printed type: extended and black for the title, condensed and tracked uppercase for labels. Courier Prime is what someone typed into the boxes. The pairing is the whole idea: printed structure, typed content.

### Hierarchy
- **Display** (900, wdth 125%, 186px at 1920 wide, line-height 0.8, -0.03em): the CLOISTER wordmark as the form's printed title, top-left. Scale it with the surface; keep weight, width and tight leading.
- **Headline** (900, wdth 70%, 34px, 0.02em): the form number ("Form CL-1") in the header block.
- **Title** (700, wdth 70%, 25–27px, 0.06–0.08em, uppercase): form name and the sub-band under the header rule ("Private ZK rollup on QoreChain").
- **Label** (700, wdth 70%, 26px, 0.09em, uppercase): field labels in the top-left of every cell. Parenthetical qualifiers drop to weight 500 at 75% opacity ("Sponsor (pays gas)").
- **Body / Typed** (Courier Prime 700, 36px, line-height 1.12): typed field values. Long hex values step down to 31px. The tagline on the Remarks line steps up to 40px.
- **Stamp** (Archivo 900, wdth 100%, 72px) with a **Stamp caption** (800, wdth 80%, 22px, 0.16em, uppercase).

### Named Rules
**The Printed vs Typed Rule.** Labels and structure are Archivo; data values are Courier Prime. A value is never set in Archivo and a label is never set in Courier Prime.

**The Ribbon Rule.** Typed entries carry only a faint ink spread (a 0.4px offset at 40% ribbon black). No heavier distress, blur or glow.

## Layout

A record is a single sheet, flat and front-on, filling the frame. The sheet is a three-column grid: a 72px tractor-feed column on each side, the form between them. The form has symmetric 56px side margins (46px top, 40px bottom) and stacks four bands: header (wordmark left, form number right, 6px ink rule under), sub-band (two uppercase phrases pushed to the ends, 2px rule under), the field grid, and a Remarks line closing the box.

The field grid is ruled with 2px ink lines on every cell edge. Columns are uneven (roughly 1.05 / 1 / 1 / 1.15) and cells may span two columns. Inside a cell the label sits at the top and the value at the bottom (12px 18px 14px padding), so the empty space between them reads as the writing area of a real form.

The carbon set is offset: the copy is inset (about 30px left, 26px top) and the white original sits further down and right beneath it, so a strip of original and its printed rules shows along the right and bottom edges against the ink field.

**The Hidden Left, Visible Right Rule.** On a record, group redacted fields toward the left and readable facts toward the right, so the eye reads "sealed" then "public" then the verdict.

## Elevation & Depth

Flat. Depth comes only from paper stacking: the canary copy carries one soft paper shadow (0 6px 14px, ink-tinted at 28%) over the original, and the original sits flat on the ink field. There are no other shadows, no blurs, no glows and no tonal gradients. The two printed rules on the original are drawn with solid single-color fills, not gradients.

### Shadow Vocabulary
- **Sheet lift** (`box-shadow: 0 6px 14px rgba(10, 9, 40, 0.28)`): the top copy of a form set over the sheet below. One per stack.

### Named Rules
**The Paper Only Rule.** Only paper casts a shadow. Ink, stamps, bars and type never do.

## Shapes

Square corners throughout: sheets, cells, redaction bars, the stamp frame. The only round forms are the 22px sprocket holes, punched in a dashed-perforation margin. The stamp is a rectangle with a 7px border plus a 4px outer ring offset by 7px, rotated a few degrees (−7deg on the cover). Rules are 2px for the grid, 6px for the header underline.

## Components

### Form Sheet
The canary copy with tractor-feed margins either side and the form in the middle. The base container for any record-shaped surface (cover, receipt, README header).

### Field Cell
Ruled 2px ink box, condensed uppercase label top-left, value bottom-left. Spans one or two columns. The value is either a typed entry or a redaction bar, never both.

### Typed Entry
Courier Prime 700 in ribbon black with a faint ink spread. Used for every public fact: batch number, signature scheme, proof system, state root, remarks. Truncate long hashes with a typed ellipsis ("5e1f 09ab 77c2 … c0a9"), never with a fade.

### Redaction Bar
A solid redaction-black block, 38px tall, with square ends. Its width varies (roughly 60–96% of the cell) to suggest the length of the hidden text. Multi-line hidden values stack bars with a 12px gap, the last bar shorter.

### Verified Stamp
Flat stamp-violet ink, double ring, uppercase VERIFIED with a small tracked caption ("Settled by proof"), rotated a few degrees, at 95% opacity. Placed in an empty part of a cell. No texture, gradient or glow.

### Tractor Feed
A 72px margin column with a 2px dashed perforation in printed-rule ink and evenly spaced 22px ink sprocket holes.

### Remarks Line
The last band of the form, closed on three sides: a small uppercase label (21px) followed by a typed sentence. This is where the tagline lives.

## Do's and Don'ts

### Do:
- **Do** make the honesty rule literal: redact exactly the fields Cloister seals to members (sender, sponsor, amount, action frames, memo) and keep readable exactly what settlement makes public (batch, chain, signature scheme, proof, state root, receipt facts).
- **Do** label every record surface as a *public copy*; Cloister never shows members' plaintext.
- **Do** place the VERIFIED stamp where it never covers a readable fact, and only on something that is actually verified (a settled batch, a checked receipt).
- **Do** keep form ink as the single print color and set labels in condensed Archivo, values in Courier Prime.
- **Do** name QoreChain as plain text in printed type ("on QoreChain").
- **Do** keep side margins symmetric inside the form (56px at cover scale).

### Don't:
- **Don't** use glows, neon, lattices, node-and-edge networks, gradient meshes or the dark crypto-banner look. The ink field around the sheet is a printing surface, not a dark-mode hero.
- **Don't** use gradients for color or depth; the only shadow is the sheet lift.
- **Don't** use the QoreChain logo or imitate its branding; text only.
- **Don't** redact something that is public on chain, or show something that is sealed. A redaction bar is a factual claim.
- **Don't** stamp VERIFIED on anything that is planned, simulated or not yet on chain.
- **Don't** add a check-mark glyph or icon to the stamp; the word is the mark.
- **Don't** round corners on sheets, cells, bars or stamps.
