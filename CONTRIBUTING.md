# Contributing to Universal Clipboard

Thanks for helping improve uclip. Small bug fixes, clear documentation and reports from real devices are welcome.

## Run locally

Use Node.js 20 or newer. From a checkout of this repository:

```sh
node --version
npm test
npm start
```

The Node server has no third-party dependencies. The development server listens at http://127.0.0.1:8787 by default. See [the README](README.md#running-the-server) for Docker, Python proxy and HTTPS configuration.

Use a separate local account and test clipboard text. Keep real passwords, session tokens, vault keys and provider credentials out of commits, screenshots and issue reports.

## Report a bug

Open an issue with:

- The operating system, browser or terminal, and Node.js version.
- The commands or steps that reproduce the problem.
- What you expected and what happened instead.
- Relevant logs with private clipboard content and credentials removed.

For clipboard backend problems, include whether you use Windows PowerShell, macOS, Wayland, X11 or Termux. Note whether the device was signed in and connected to the server.

## Submit a pull request

1. Create a branch for one coherent change.
2. Update the relevant documentation when behavior or configuration changes.
3. For behavior changes, add or update a regression test in `test/` where practical.
4. Run `npm test` and describe the result in the pull request.
5. Describe the problem, the resulting behavior and any platform checks you performed.

Automated tests do not replace checks on real hardware. If your change touches an OS clipboard backend, the Android PWA, Google sign-in or email delivery, state which real platforms or providers you exercised and which remain unverified.
