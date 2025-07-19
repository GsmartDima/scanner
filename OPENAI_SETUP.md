# OpenAI Enhanced Report Generation Setup

## Overview

The scanner now includes AI-powered enhanced report generation using OpenAI's GPT-4 mini model. This creates more professional, executive-level reports with better analysis and recommendations.

## Setup Instructions

### 1. Install Dependencies

```bash
pip install openai>=1.12.0
```

### 2. Configure Environment Variables

Create a `.env` file in the project root with your OpenAI configuration:

```bash
# OpenAI Configuration
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4o-mini
OPENAI_ENABLED=true
```

**IMPORTANT**: Never commit your actual API key to version control. The `.env` file should be in your `.gitignore`.

### 3. Alternative: Export Environment Variables

Instead of using a `.env` file, you can export environment variables directly:

```bash
export OPENAI_API_KEY="your-openai-api-key-here"
export OPENAI_MODEL="gpt-4o-mini"
export OPENAI_ENABLED="true"
```

### 4. Restart the Application

After configuring your API key, restart the scanner application:

```bash
python3 api.py
```

## Features

When enabled, the enhanced report generation provides:

- **Executive Summary**: AI-generated professional summary highlighting key risks
- **Risk Analysis**: Detailed business impact analysis
- **Prioritized Recommendations**: AI-prioritized action items based on risk level
- **Compliance Notes**: Relevant compliance considerations
- **Strategic Planning**: Long-term security strategy recommendations

## Security Notes

- Your OpenAI API key is never stored in the codebase
- API calls are only made during report generation
- Scan data is summarized before being sent to OpenAI
- No sensitive information like passwords or tokens are included in API calls

## Fallback Behavior

If OpenAI is not configured or fails:
- The system automatically falls back to standard report generation
- All scanning functionality continues to work normally
- You'll see a warning in the logs but no errors

## Cost Estimation

- GPT-4 mini costs approximately $0.15 per 1M input tokens and $0.60 per 1M output tokens
- Each enhanced report uses approximately 2,000-4,000 tokens
- Cost per report: ~$0.002-0.004 (less than half a cent per report)

## Troubleshooting

### "Enhanced report generation disabled"
- Check that `OPENAI_ENABLED=true` is set
- Verify your API key is correctly configured
- Ensure the `openai` package is installed

### API Errors
- Verify your OpenAI API key has sufficient credits
- Check for any rate limiting from OpenAI
- Review the application logs for specific error messages

### Fallback to Standard Reports
- If AI generation fails, the system automatically uses standard templates
- This ensures reports are always generated, even if AI enhancement fails 