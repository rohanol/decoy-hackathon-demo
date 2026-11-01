# DeceptionGraph Research Portal — visual reference (for M4)

Owner: M1 (Pashmee). The normal app is `dg-soc/demo-app` (`demo-app-01`). This
page lets M4 keep the decoy side (`web-decoy-01` behind `gateway-01`) visually
consistent, so a diverted session is not dropped into an obviously different
site. Consistency is not a promise of undetectability: nothing in the project
claims the diversion cannot be noticed.

The source of truth is `demo-app/portal/static/portal.css` and
`demo-app/portal/templates/base.html`. Screenshots are in `portal/` next to this
file, taken from the running app at 1280×800 (and 390 px wide for mobile).

## Brand

- Name: **DeceptionGraph Research Portal**. Wordmark: "DeceptionGraph" bold +
  "Research Portal" regular, neutral grey.
- Mark: `demo-app/portal/static/mark.svg`, 28 px: a navy rounded square with
  three nodes (two green, one white) and two green edges. Original artwork.
- Fictional organisation. Do not add any real institute's name, logo, domain or
  people. The footer always says: "Demonstration portal. All people, projects
  and data are fictional."

## Colours

User correction (1 November 2026): preserve the existing SOC's black, white and
neon-green appearance. This supersedes the earlier light institutional palette.
The application structure, synthetic accounts, routing and telemetry stay intact.

| Token | Hex | Use |
|---|---|---|
| `--navy` | `#050505` | Top bar |
| `--navy-2` | `#151515` | Active / hover nav item and input surfaces |
| `--teal` | `#39ff88` | Links, primary buttons, eyebrow text, tags |
| `--teal-weak` | `rgba(57,255,136,.1)` | Tag background, input focus ring |
| `--ink` | `#f4f4f2` | Body text and stat numbers |
| `--muted` | `#a6a6a3` | Secondary text, dates |
| `--line` | `#1f1f1f` | Card borders, table rules |
| `--bg` | `#050505` | Page background |
| `--card` | `#0c0c0c` | Cards, footer |
| `--danger` | `#ff7aa2` on translucent pink | Login error alert |

Typography: system UI stack (`system-ui, -apple-system, "Segoe UI", Roboto,
…`); no web fonts, since the lab has no internet. H1 32 px on Home and 28 px
elsewhere; card titles 17 px; body 16 px; line height 1.5.

## Layout

- **Top bar:** 64 px, full-width black. Inside a 1120 px container: mark +
  wordmark, then the nav links, then the account area on the right ("Sign in"
  green button; when signed in, the name plus a "Sign out" outline button).
- **Main:** 1120 px container, 32 px top padding. Cards: near-black, 1 px
  `--line` border, 14 px radius, 20–22 px padding. Two-column grids at 20 px
  gap, collapsing to one column under 800 px.
- **Footer:** 64 px, near-black, top border, copyright left and the fictional notice right.

## Navigation

`Home · Reports · Resources · Search`, plus `Dashboard` only when signed in.
The active item gets a `--navy-2` pill. No other menu, admin link, or any
control or hint about routing, gateways, decoys or destinations. The
participant-facing UI must never expose one.

## Routes and pages

| Path | Page | Content |
|---|---|---|
| `/` | Home | Eyebrow "Internal research workspace", H1, lead, search bar; Quick links card; Announcements card; Recent reports card |
| `/login` | Sign in | Centred 400 px card: Email, Password, full-width "Sign in". Wrong credentials: red alert "The email or password is incorrect." with HTTP 401 |
| `/dashboard` | Dashboard (signed in) | "Welcome back, <name>", role · email; three stat tiles (reports, datasets, open tasks); "My tasks" table; "Recently updated" list |
| `/search?q=` | Search | Search bar; "N results for “q”"; result cards with a Report/Dataset tag; empty-state hint |
| `/reports` | Reports | Two-column cards: group eyebrow, title link, abstract, authors · date |
| `/reports/<slug>` | Report | Breadcrumb; card with group/date, title, authors, Abstract, numbered Contents, "Full text is available to group members on request." |
| `/resources` | Dataset catalogue | Table: ID (mono), Dataset, Rows, Owner, Access tag. No downloads |
| anything else | Not found | Centred card "Page not found", "Back to home" button, HTTP 404 |

Screenshots: `portal/home.png`, `login.png`, `login-failed.png`,
`dashboard.png`, `search.png`, `reports.png`, `report.png`, `resources.png`,
`not-found.png`, `home-mobile.png`.

## Account behaviour

- Two synthetic accounts (`researcher@example.com`, `analyst@example.com`); the
  passwords are in `demo-app/README.md`.
- Sign-in sets the portal's own `portal_session` cookie (HttpOnly, SameSite=Lax,
  signed); signing out clears it. `/dashboard` redirects to `/login` when signed
  out. Unknown accounts and wrong passwords get the same message and timing.
- **The portal accepts no honeytoken.** The planted portal credential
  (`tok_portal_01`, notes.txt) belongs to the web decoy's own login, as today.
  If M4 wants a diverted session's `/login` to look like this page, it should
  reuse the layout and the error copy, with its own existing credential handling
  and telemetry. Do not copy the portal's accounts into the decoy.

## What M4 should mirror, and what not

Mirror: top bar, nav order, colours, card style, footer notice, page titles
(`<page> · DeceptionGraph Research Portal`), the login card and error copy, and
the 404 card.

Do not mirror:
- the portal's accounts or session cookie name (the gateway has its own cookie);
- `/readyz`;
- any route the decoy does not actually serve.

`/backup/backup.zip` exists only on the decoy (M4); the portal 404s it.
