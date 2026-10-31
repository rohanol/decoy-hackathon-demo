# Codex setup: recommended tools (MCP servers)

Codex can use extra tools through MCP servers, configured in `~/.codex/config.toml`. For this
design playground, one tool matters most: a browser Codex can drive, so it can open the app,
click through the screens and save screenshots itself.

Versions are pinned (checked on npm, 31 Oct 2026), as the team rules in `dg-soc/AGENTS.md`
section 4 require. Everything runs on your laptop with `npx`; Node 20+ is required.

## 1. Playwright MCP (must have)

Lets Codex open `http://127.0.0.1:5174`, switch variants, click through all seven screens and
save 1440x900 screenshots into `reference/<variant>/`. Without it, Codex cannot see the app and
you take screenshots by hand.

`--browser msedge` uses the Edge already installed on Windows, so no extra browser download.
`--isolated` keeps its browser profile in memory, separate from your own Edge.

```toml
# ~/.codex/config.toml   (Windows: C:\Users\<you>\.codex\config.toml)
[mcp_servers.playwright]
command = "npx"
args = ["-y", "@playwright/mcp@0.0.83", "--browser", "msedge", "--isolated", "--viewport-size", "1440x900"]
```

On a Mac or Linux laptop without Edge, use `"chrome"` instead of `"msedge"`.

Or from a terminal (same result):

```bash
codex mcp add playwright -- npx -y @playwright/mcp@0.0.83 --browser msedge --isolated --viewport-size 1440x900
```

Quick test: start the playground (`START_HERE.md`), then ask Codex: "Use Playwright to open
http://127.0.0.1:5174/?variant=a and save a screenshot to reference/a/overview.png."

## 2. Chrome DevTools MCP (nice to have)

Lets Codex read the browser console, inspect CSS and check contrast and layout problems on a
running page. Useful when a variant looks wrong and Codex needs to find why.

```toml
[mcp_servers.chrome-devtools]
command = "npx"
args = ["-y", "chrome-devtools-mcp@1.12.0", "--isolated"]
```

It drives Chrome. If Chrome is not installed, skip this one; Playwright covers screenshots.

## 3. Context7 (optional)

Gives Codex current documentation for React 18, Vite 5 and TypeScript, so it does not guess
outdated APIs. Needs a free API key from context7.com.

```toml
[mcp_servers.context7]
command = "npx"
args = ["-y", "@upstash/context7-mcp@4.4.4", "--api-key", "YOUR_KEY"]
```

Never commit a key: this file lives in your home folder, not the repo.

## What not to add

- Anything that deploys, publishes or pushes (Vercel, Netlify, GitHub write tools). This is a local
  playground.
- Design-system or UI-kit generators that pull in new libraries. The rules forbid new dependencies by
  default and webfonts or CDNs entirely (`AGENTS.md` section 5).
- A Figma connector, unless Pashmee's designs are in Figma: then a Figma plugin from Codex's plugin
  list helps it read frames. Her current design source is `../frontend/DESIGN_SPEC.md`, not Figma.

## After editing config.toml

Restart Codex. Ask it "which MCP tools do you have?" and check that `playwright` is listed before
starting design tasks.
