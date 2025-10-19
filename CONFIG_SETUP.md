# Configuration Setup

## Wiremock Configuration

To use the Wiremock dashboard, you need to set up your configuration file.

### Option 1: Configuration File (Recommended)

1. Copy the example configuration file:
   ```bash
   cp wiremock_config.json.example wiremock_config.json
   ```

2. Edit `wiremock_config.json` with your actual credentials:
   - Replace all placeholder values with your real API keys, tokens, and URLs
   - Make sure to use the correct Wiremock server URL
   - Update all authentication credentials

### Option 2: Environment Variables

You can also set these as environment variables instead of using the config file:

```bash
export WIREMOCK_BASEURL="https://your-wiremock-server.com"
export WIREMOCK_ADMIN_USERNAME="your_username"
export WIREMOCK_ADMIN_PASSWORD="your_password"
# ... set all other variables
```

### Security Notes

- **Never commit `wiremock_config.json`** to version control
- The file is already added to `.gitignore`
- Use `wiremock_config.json.example` as a template
- Keep your credentials secure and private

### File Structure

```
├── wiremock_config.json          # Your actual config (DO NOT COMMIT)
├── wiremock_config.json.example  # Template file (safe to commit)
├── logs/                         # Generated logs (DO NOT COMMIT)
└── .gitignore                   # Contains sensitive file patterns
```

### Troubleshooting

If you get "No module named 'pydantic'" error:
- The system uses a custom configuration class, not Pydantic
- No additional dependencies are required
- Make sure you're using the correct Python environment
