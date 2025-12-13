#!/bin/bash

# Quick helper script to view deployment information
# Usage: ./show_deployment_info.sh

clear

echo "════════════════════════════════════════════════════════════════════════"
echo "                    NEO4J DASHBOARD - DEPLOYMENT INFO                    "
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Server Requirements
echo "📊 SERVER REQUIREMENTS:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  Minimum:      4 cores | 8 GB RAM  | 50 GB SSD"
echo "  Recommended:  8 cores | 16 GB RAM | 100 GB NVMe SSD"
echo "  OS Required:  Ubuntu 22.04 LTS"
echo ""

# SSH Public Key
echo "🔐 SSH PUBLIC KEY (Share with DevOps):"
echo "────────────────────────────────────────────────────────────────────────"
cat deployment_ssh_key.pub
echo ""

# Ports
echo "🔥 FIREWALL PORTS:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  Allow Public:  22 (SSH), 80 (HTTP), 443 (HTTPS)"
echo "  Deny External: 5432, 7474, 7687, 8000, 27017, 8080, 8081"
echo ""

# Documents
echo "📚 DOCUMENTATION FILES:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  1. SUMMARY_FOR_DEVOPS.md         - Send this first!"
echo "  2. DEVOPS_VM_REQUEST.md          - Complete requirements"
echo "  3. DEVOPS_CHECKLIST.md           - Step-by-step deployment"
echo "  4. DEPLOYMENT_GUIDE.md           - Full documentation"
echo "  5. DEPLOYMENT_README.md          - Documentation index"
echo "  6. SSH_KEY_INFO.md               - SSH key guide"
echo ""

# Next Steps
echo "🚀 NEXT STEPS:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  1. Review:  cat DEPLOYMENT_README.md"
echo "  2. Send to DevOps:  SUMMARY_FOR_DEVOPS.md + deployment_ssh_key.pub"
echo "  3. Secure private key:  chmod 600 deployment_ssh_key"
echo "  4. Wait for VM details from DevOps team"
echo ""

# Quick Commands
echo "💡 QUICK COMMANDS:"
echo "────────────────────────────────────────────────────────────────────────"
echo "  View summary:       cat SUMMARY_FOR_DEVOPS.md"
echo "  View public key:    cat deployment_ssh_key.pub"
echo "  View full guide:    cat DEPLOYMENT_GUIDE.md"
echo "  Connect to VM:      ssh -i deployment_ssh_key username@<VM-IP>"
echo ""

echo "════════════════════════════════════════════════════════════════════════"
echo "                    ✅ READY TO SEND TO DEVOPS TEAM                      "
echo "════════════════════════════════════════════════════════════════════════"
echo ""
