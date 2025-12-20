# Contributing to P2PCF-WS

Thank you for your interest in contributing! 🎉

## How to Contribute

### Reporting Issues

- Check existing issues first
- Provide clear reproduction steps
- Include relevant logs and configuration

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test locally: `npm run dev`
5. Commit with clear messages: `git commit -m "feat: add xyz"`
6. Push and create a PR

### Code Style

- TypeScript for all code
- Run `npx tsc --noEmit` before committing
- Add JSDoc comments for public APIs

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/p2pcf-ws.git
cd p2pcf-ws

# Install dependencies
npm install

# Run locally
npm run dev

# Deploy to your own Cloudflare account
npx wrangler login
npm run deploy
```

## Project Structure

```
p2pcf-ws/
├── src/
│   ├── index.ts          # Worker entry point
│   └── SignalingRoom.ts  # Durable Object implementation
├── wrangler.toml         # Cloudflare configuration
├── package.json
├── tsconfig.json
├── README.md
├── LICENSE
└── CONTRIBUTING.md
```

## Questions?

Open an issue or reach out to the maintainers!
