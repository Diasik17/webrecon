#!/usr/bin/env python3
"""
WebRecon - Web Application Reconnaissance Toolkit for Bug Bounty

All-in-one recon: JS analysis, subdomain enumeration, API fuzzing,
secret detection, security header audit, and more.

Usage:
    python3 webrecon.py -u https://example.com
    python3 webrecon.py -u https://example.com --deep
    python3 webrecon.py -u https://example.com --deep --probe
    python3 webrecon.py -f urls.txt
    python3 webrecon.py -d /path/to/js/files
"""

import re
import sys
import os
import json
import random
import argparse
import hashlib
import signal
import socket
import concurrent.futures
from urllib.parse import urljoin, urlparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import requests
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "2.0"

BANNER = f"""
{Fore.RED}    ╦ ╦╔═╗╔╗ ╦═╗╔═╗╔═╗╔═╗╔╗╔
    ║║║║╣ ╠╩╗╠╦╝║╣ ║  ║ ║║║║
    ╚╩╝╚═╝╚═╝╩╚═╚═╝╚═╝╚═╝╝╚╝{Style.RESET_ALL}
    {Fore.CYAN}Web Recon Toolkit v{VERSION}{Style.RESET_ALL}
    {Fore.WHITE}Bug Bounty Edition{Style.RESET_ALL}

{Fore.YELLOW}⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡾⠋⠉⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⠃⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢀⡏⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣠⣤⣤⣤⣤⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡏⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠴⠒⠊⠉⠉⠀⠀⣿⣿⣿⠿⠋⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⢀⡠⠼⠴⠒⠒⠒⠒⠦⠤⠤⣄⣀⠀⢀⣠⠴⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⣼⠿⠋⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣇⠔⠂⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⠿⠋⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠖⠋⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢰⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⠤⠒⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⡟⠀⣠⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⢻⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⡤⠤⢴
⠀⠀⠀⠀⠀⠀⣸⠁⣾⣿⣀⣽⡆⠀⠀⠀⠀⠀⠀⠀⢠⣾⠉⢿⣦⠀⠀⠀⢸⡀⠀⠀⢀⣠⠤⠔⠒⠋⠉⠉⠀⠀⠀⠀⢀⡞
⠀⠀⠀⠀⠀⢀⡏⠀⠹⠿⠿⠟⠁⠀⠰⠦⠀⠀⠀⠀⠸⣿⣿⣿⡿⠀⠀⠀⢘⡧⠖⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡼⠀
⠀⠀⠀⠀⠀⣼⠦⣄⠀⠀⢠⣀⣀⣴⠟⠶⣄⡀⠀⠀⡀⠀⠉⠁⠀⠀⠀⠀⢸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀
⠀⠀⠀⠀⢰⡇⠀⠈⡇⠀⠀⠸⡾⠁⠀⠀⠀⠉⠉⡏⠀⠀⠀⣠⠖⠉⠓⢤⢸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀
⠀⠀⠀⠀⠀⢧⣀⡼⠃⠀⠀⠀⢧⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⣧⠀⠀⠀⣸⢹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡰⠃⠀⠀⠀
⠀⠀⠀⠀⠀⠈⢧⡀⠀⠀⠀⠀⠘⣆⠀⠀⠀⢠⠏⠀⠀⠀⠀⠈⠳⠤⠖⠃⡟⠀⠀⠀⢾⠛⠛⠛⠛⠛⠛⠛⠛⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠙⣆⠀⠀⠀⠀⠈⠦⣀⡴⠋⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⠙⢦⠀⠀⠘⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⡇⠙⠦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⠴⠋⠸⡇⠈⢳⡀⠀⢹⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡼⣀⠀⠀⠈⠙⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠀⠀⠀⠀⣷⠴⠚⠁⠀⣀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡴⠁⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣆⡴⠚⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣼⢷⡆⠀⣠⡴⠧⣄⣇⠀⠀⠀⠀⠀⠀⠀⢲⠀⡟⠀⠀⠀⠀⠀⠀⠀⢀⡇⣠⣽⢦⣄⢀⣴⣶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⡿⣼⣽⡞⠁⠀⠀⠀⢹⡀⠀⠀⠀⠀⠀⠀⠈⣷⠃⠀⠀⠀⠀⠀⠀⠀⣼⠉⠁⠀⠀⢠⢟⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣷⠉⠁⢳⠀⠀⠀⠀⠈⣧⠀⠀⠀⠀⠀⠀⠀⣻⠀⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠏⠀⠀⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠹⡆⠀⠈⡇⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⠀⠀⠀⣸⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢳⡀⠀⠙⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⣰⠃⠀⠀⠀⠀⢀⡄⠀⢠⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢳⡀⣰⣀⣀⣀⠀⠀⠀⠘⣦⣀⠀⠀⠀⡇⠀⠀⠀⢀⡴⠃⠀⠀⠀⠀⠀⢸⡇⢠⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⠉⠀⠀⠈⠉⠉⠉⠙⠻⠿⠾⠾⠻⠓⢦⠦⡶⡶⠿⠛⠛⠓⠒⠒⠚⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀{Style.RESET_ALL}
{Fore.WHITE}         by {Fore.RED}g00f1x{Style.RESET_ALL}
"""

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

ENDPOINT_PATTERNS = [
    # REST API paths
    r"""(?:"|'|`)(\/api\/[a-zA-Z0-9_\-\/\.\{\}\?&=\[\]%:@\$\+\*\,;!~]+?)(?:"|'|`)""",
    r"""(?:"|'|`)(\/v[0-9]+\/[a-zA-Z0-9_\-\/\.\{\}\?&=\[\]%:@\$\+\*\,;!~]+?)(?:"|'|`)""",
    r"""(?:"|'|`)(\/graphql[a-zA-Z0-9_\-\/\.\{\}]*)(?:"|'|`)""",

    # Generic relative paths (2+ segments)
    r"""(?:"|'|`)(\/[a-zA-Z0-9_\-]+\/[a-zA-Z0-9_\-\/\.\{\}\?&=\[\]%]+?)(?:"|'|`)""",

    # Full URLs in strings
    r"""(?:"|'|`)(https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}[a-zA-Z0-9_\-\/\.\?\&\=\#\[\]%:@\$\+\*\,;!~]*)(?:"|'|`)""",

    # Fetch/axios/XMLHttpRequest calls
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch|head|options)|\.open)\s*\(\s*(?:"|'|`)(.*?)(?:"|'|`)""",

    # URL assignments
    r"""(?:url|uri|endpoint|baseUrl|base_url|apiUrl|api_url|href|action|src)\s*[:=]\s*(?:"|'|`)((?:\/|https?:\/\/)[^\s"'`]+)(?:"|'|`)""",

    # Template literals with paths
    r"""`((?:\/|https?:\/\/)[^`]*?\$\{[^}]+\}[^`]*?)`""",
]

SECRET_PATTERNS = {
    # Cloud provider keys
    "AWS Access Key": r"""AKIA[0-9A-Z]{16}""",
    "AWS Secret Key": r"""(?:aws.{0,20}(?:secret|key).{0,20}[\"\']?\s*[:=]\s*[\"\']?)([A-Za-z0-9\/\+=]{40})""",
    "Google API Key": r"""AIza[0-9A-Za-z\-_]{35}""",
    "Google OAuth": r"""[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com""",
    "Firebase Key": r"""AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}""",

    # Platform tokens (strict prefixes)
    "GitHub Token": r"""gh[pousr]_[A-Za-z0-9_]{36,255}""",
    "Slack Token": r"""xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*""",
    "Slack Webhook": r"""https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}""",
    "Stripe Key": r"""(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}""",
    "Twilio API Key": r"""SK[0-9a-fA-F]{32}""",
    "Mailgun API Key": r"""key-[0-9a-zA-Z]{32}""",
    "SendGrid Key": r"""SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}""",
    "Square Token": r"""sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}""",
    "Shopify Token": r"""shpat_[a-fA-F0-9]{32}""",
    "Mapbox Token": r"""pk\.[a-zA-Z0-9]{60,}""",
    "Telegram Bot Token": r"""(?:["'`])[0-9]{5,10}:[A-Za-z0-9_-]{35}(?:["'`])""",
    "Discord Webhook": r"""https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+""",
    "Heroku API Key": r"""[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}""",

    # Auth tokens — strict: must look like actual encoded tokens, not English words
    "JWT Token": r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}""",
    "Bearer Token": r"""["']Bearer\s+[A-Za-z0-9\-_\.~\+\/]{20,}["']""",
    "Basic Auth Header": r"""["']Basic\s+[A-Za-z0-9\+\/]{16,}={0,2}["']""",
    "Authorization Header": r"""["']Authorization["']\s*:\s*["']((?:Bearer|Basic|Token)\s+[A-Za-z0-9\-_\.~\+\/=]{16,})["']""",
    "Private Key": r"""-----BEGIN\s(?:RSA|EC|DSA|OPENSSH)?\s?PRIVATE KEY-----""",

    # Credentials in code
    "Password in URL": r"""https?://[^\s:@"']+:([^\s@"']{6,})@[a-zA-Z0-9][\w.-]+\.[a-zA-Z]{2,}""",
    "Hardcoded Password": r"""(?:password|passwd|pwd|secret)\s*[:=]\s*["']([^"'\s]{6,})["']""",
    "API Key Generic": r"""(?:api[_\-]?key|apikey|api[_\-]?secret|secret[_\-]?key)\s*[:=]\s*["']([A-Za-z0-9\-_\.]{20,})["']""",

    # Cloud resources
    "S3 Bucket": r"""(?:[a-zA-Z0-9\-]+\.)?s3[\.-](?:us|eu|ap|sa|ca|me|af)-?[a-z]*-?\d?\.amazonaws\.com""",
    "S3 Bucket Path": r"""s3:\/\/([a-zA-Z0-9\-\.]+)""",
    "Azure Storage": r"""[a-zA-Z0-9]+\.blob\.core\.windows\.net""",
    "GCP Bucket": r"""storage\.googleapis\.com\/[a-zA-Z0-9\-\.]+""",
    "Cloudinary URL": r"""cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-zA-Z0-9]+""",
}

SENSITIVE_INFO_PATTERNS = {
    "IP Address (Private)": r"""(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})""",
    "Internal URL": r"""https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?[^\s"'`]*""",
    "Staging/Dev URL": r"""https?://(?:staging|dev|test|uat|preprod|internal)[\.\-][^\s"'`]+""",
    "Debug/Admin Endpoint": r"""(?:"|'|`)(/(?:admin|debug|staging|internal|_debug|__debug|phpinfo|elmah|trace|diagnostics)(?:/[^\s"'`]*)?)(?:"|'|`)""",
}

# Domains that are noise in sensitive info / domains output (libraries, docs, etc.)
NOISE_DOMAINS = {
    # Dev/code platforms
    "github.com", "gitlab.com", "bitbucket.org",
    "npmjs.com", "npmjs.org", "yarnpkg.com",
    "mozilla.org", "developer.mozilla.org", "mdn.io",
    "developer.chrome.com", "chromium.org",
    "microsoft.com", "docs.microsoft.com", "learn.microsoft.com",
    "apple.com", "developer.apple.com", "webkit.org",
    # JS frameworks/libraries
    "vuejs.org", "reactjs.org", "angular.io", "svelte.dev",
    "nodejs.org", "deno.land",
    "jquery.com", "jquerymobile.com", "jqueryui.com",
    "getbootstrap.com", "momentjs.com", "lodash.com",
    "webpack.js.org", "babeljs.io", "eslint.org", "prettier.io",
    "typescriptlang.org", "tc39.es", "ecma-international.org",
    "summernote.org", "ckeditor.com", "tinymce.com",
    "jspdf.com", "sciactive.com", "pnotify.com",
    "wamp.ws", "api.wamp.ws", "crossbar.io",
    "socket.io", "sockjs.org",
    # Social / video / media
    "youtube.com", "youtube-nocookie.com", "youtu.be", "ytimg.com",
    "vimeo.com", "player.vimeo.com", "dailymotion.com",
    "instagram.com", "pinterest.com",
    "twitter.com", "x.com", "twimg.com",
    "facebook.com", "facebook.net", "fbcdn.net",
    "linkedin.com", "reddit.com", "tumblr.com",
    "tiktok.com", "snapchat.com", "whatsapp.com",
    "telegram.org", "t.me",
    "qq.com", "v.qq.com", "weibo.com", "weixin.qq.com",
    # Cloud/storage docs (not the actual buckets — those are caught by secret patterns)
    "min.io", "docs.min.io", "slack.min.io",
    "docs.aws.amazon.com", "cloud.google.com", "azure.microsoft.com",
    # CDN / analytics / tracking
    "cloudflare.com", "cdnjs.cloudflare.com",
    "jsdelivr.net", "unpkg.com", "stackpath.bootstrapcdn.com",
    "google.com", "googleapis.com", "gstatic.com",
    "googletagmanager.com", "google-analytics.com",
    "googlesyndication.com", "googleadservices.com",
    "sentry.io", "sentry-cdn.com",
    "hotjar.com", "clarity.ms", "newrelic.com",
    "segment.io", "segment.com", "mixpanel.com", "amplitude.com",
    "polyfill.io", "hcaptcha.com", "recaptcha.net",
    # Fonts
    "fonts.googleapis.com", "fonts.gstatic.com",
    "use.typekit.net", "fast.fonts.net",
    # Payment (widget/embed, not API)
    "js.stripe.com", "checkout.stripe.com",
    "paypal.com", "paypalobjects.com",
    # Maps
    "maps.googleapis.com", "maps.google.com",
    "api.mapbox.com", "openstreetmap.org", "leafletjs.com",
    # Misc noise
    "gravatar.com", "wp.com", "wordpress.com", "wordpress.org",
    "caniuse.com", "stackoverflow.com", "wikipedia.org",
    "creativecommons.org", "opensource.org",
    "example.com", "example.org", "example.net", "test.com",
    "your-domain.com", "your-domain-1.com", "your-domain-2.com",
    "yourdomain.com", "yoursite.com", "your-site.com",
    "someurl.com", "someuri.com", "somepath.imgix.net",
    "mysite.com", "mysite.cloudinary.com", "subdomain.mysite.com",
    "my.base.url", "site.com", "your-n8n-instance.com",
    "w3schools.com", "codepen.io", "jsfiddle.net",
    "medium.com", "dev.to", "hashnode.dev",
    "bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
    "fontawesome.com", "use.fontawesome.com",
    # RU/CIS specific
    "yandex.ru", "mc.yandex.ru", "yastatic.net", "yandex.net",
    "vk.com", "vkontakte.ru", "top-fwz1.mail.ru", "mail.ru",
    "ok.ru", "odnoklassniki.ru",
    # Recaptcha / hcaptcha
    "hcaptcha.com", "recaptcha.net",
    "sentry-cdn.com",
    "code.jquery.com",
}

JS_LINK_PATTERNS = [
    r"""<script[^>]+src=["']([^"']+\.js[^"']*)["']""",
    r"""(?:"|'|`)((?:https?:)?\/\/[^\s"'`]+\.js(?:\?[^\s"'`]*)?)(?:"|'|`)""",
    r"""(?:src|href)\s*[:=]\s*(?:"|'|`)([^"'`<>]+\.js(?:\?[^"'`<>]*)?)(?:"|'|`)""",
    r"""importScripts\s*\(\s*(?:"|'|`)([^"'`]+)(?:"|'|`)""",
]

FILTERED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".mp3", ".map"}

FILTERED_PATHS = {
    # XML/HTML namespaces & specs
    "/w3.org/", "/schema.org/", "/xmlns", "/dtd/", "/xhtml/", "/xml/", "/mathml",
    "/1999/", "/1998/", "/2000/", "/2001/", "/2005/", "/TR/",
    "www.w3.org", "w3.org/", "schemas.xmlsoap.org", "schemas.microsoft.com",
    "purl.org/", "ogp.me/", "rdfs.org/",
    # Common 3rd party noise
    "jquery.min.js", "font-awesome", "bootstrap.min.js",
    "google-analytics", "googletagmanager", "googleapis.com/css",
    "facebook.com/tr", "facebook.net/", "fbcdn.net/",
    "twitter.com/", "platform.twitter",
    "connect.facebook", "graph.facebook",
    "sentry.io/", "hotjar.com/", "clarity.ms/",
    "polyfill.io/", "cdn.jsdelivr.net/", "cdnjs.cloudflare.com/",
    "unpkg.com/", "stackpath.bootstrapcdn",
    # Framework build artifacts (not real API endpoints)
    "/_next/static/", "/_next/image", "/_next/data/",
    "/__next/", "/_nuxt/", "/.nuxt/",
    "/webpack", "/node_modules/", "/chunk-", "/chunks/",
    "/cdn-cgi/", "/cloudflare-static/",
    "/site.webmanifest", "/manifest.json", "/browserconfig.xml",
    "/favicon", "/apple-touch-icon",
}

# Params patterns — extract what JS sends to APIs
PARAM_PATTERNS = [
    # JSON body keys: { "key": value }
    r"""(?:body|data|params|payload|json)\s*[:=]\s*(?:JSON\.stringify\s*\()?\s*\{([^}]{5,500})\}""",
    # FormData.append("key", ...)
    r"""\.append\s*\(\s*["']([a-zA-Z0-9_\-]+)["']""",
    # URLSearchParams
    r"""URLSearchParams\s*\(\s*\{([^}]+)\}""",
    # .set("key", ...) / .get("key")
    r"""\.(?:set|get|has|delete)\s*\(\s*["']([a-zA-Z0-9_\-]+)["']""",
    # Direct key: value in object literals near fetch/axios
    r"""["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']\s*:\s*(?:["'][^"']*["']|[a-zA-Z_]\w*|\d+|true|false|null)""",
    # query string building: "?key=" or "&key="
    r"""[?&]([a-zA-Z0-9_\-]{2,30})=""",
    # Input field names in HTML-like strings
    r"""name\s*=\s*["']([a-zA-Z0-9_\-]{2,30})["']""",
    # GraphQL variables
    r"""\$([a-zA-Z_][a-zA-Z0-9_]{1,30})\s*:\s*(?:String|Int|Float|Boolean|ID|Input|\[)""",
]

SECURITY_HEADERS_CHECK = {
    "strict-transport-security": ("HIGH", "HSTS missing — SSL stripping possible"),
    "content-security-policy": ("HIGH", "CSP missing — XSS risk"),
    "x-content-type-options": ("MEDIUM", "MIME sniffing possible"),
    "x-frame-options": ("MEDIUM", "Clickjacking possible"),
    "referrer-policy": ("LOW", "May leak URLs to third parties"),
    "permissions-policy": ("LOW", "Browser features unrestricted"),
    "x-xss-protection": ("LOW", "Legacy XSS protection not set"),
}

INFO_LEAK_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-runtime", "x-version", "x-generator", "x-debug", "x-debug-token",
    "x-php-version", "x-drupal-cache", "x-varnish", "x-litespeed-cache",
    "x-turbo-charged-by", "x-pingback", "x-redirect-by",
]

TECH_SIGNATURES = {
    "server": {
        "nginx": "Nginx", "apache": "Apache", "iis": "IIS/Microsoft",
        "cloudflare": "Cloudflare", "litespeed": "LiteSpeed",
        "openresty": "OpenResty", "gunicorn": "Gunicorn/Python",
        "uvicorn": "Uvicorn/Python", "werkzeug": "Flask/Python",
        "kestrel": "Kestrel/.NET", "caddy": "Caddy", "cowboy": "Erlang",
    },
    "x-powered-by": {
        "php": "PHP", "asp.net": "ASP.NET", "express": "Express/Node.js",
        "next.js": "Next.js", "nuxt": "Nuxt.js", "django": "Django",
        "rails": "Ruby on Rails", "laravel": "Laravel",
        "flask": "Flask", "spring": "Spring/Java", "servlet": "Java Servlet",
    },
}

# ---------------------------------------------------------------------------
# Core classes
# ---------------------------------------------------------------------------

class JSFetcher:
    """Fetches JS content from URLs or local files."""

    def __init__(self, headers=None, timeout=15, proxy=None):
        self.session = requests.Session()
        self.session.headers.update(headers or {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        self.timeout = timeout
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.seen_hashes = set()

    def fetch_url(self, url):
        if any(c in url for c in '<>{};') or len(url) > 2000:
            return None
        try:
            resp = self.session.get(url, timeout=self.timeout, verify=False)
            resp.raise_for_status()
            content = resp.text
            h = hashlib.md5(content.encode()).hexdigest()
            if h in self.seen_hashes:
                return None
            self.seen_hashes.add(h)
            return content
        except requests.RequestException as e:
            print(f"  {Fore.RED}[!] Failed to fetch {url}: {e}{Style.RESET_ALL}")
            return None

    def read_file(self, path):
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            h = hashlib.md5(content.encode()).hexdigest()
            if h in self.seen_hashes:
                return None
            self.seen_hashes.add(h)
            return content
        except OSError as e:
            print(f"  {Fore.RED}[!] Failed to read {path}: {e}{Style.RESET_ALL}")
            return None

    @staticmethod
    def _is_external_js(js_url, target_domain):
        """Check if a JS URL belongs to an external/3rd-party domain."""
        parsed = urlparse(js_url)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        for ext in NOISE_DOMAINS:
            if host == ext or host.endswith("." + ext):
                return True
        if target_domain and not (host == target_domain or host.endswith("." + target_domain)):
            return True
        return False

    def discover_js_urls(self, page_url):
        """Crawl an HTML page and extract all linked JS files (skip external/3rd-party)."""
        js_urls = set()
        skipped = set()

        target_domain = urlparse(page_url).hostname

        # Detect external redirects — if the page redirected to a different domain, skip it
        try:
            resp = self.session.get(page_url, timeout=self.timeout, verify=False)
            final_domain = urlparse(resp.url).hostname
            td = target_domain.removeprefix("www.")
            fd = final_domain.removeprefix("www.") if final_domain else ""
            if final_domain and target_domain and fd != td and not fd.endswith("." + td) and not td.endswith("." + fd):
                print(f"  {Fore.YELLOW}[*] Skipped {page_url} — redirects to external {final_domain}{Style.RESET_ALL}")
                return js_urls
            content = resp.text
            h = hashlib.md5(content.encode()).hexdigest()
            if h in self.seen_hashes:
                return js_urls
            self.seen_hashes.add(h)
        except requests.RequestException as e:
            print(f"  {Fore.RED}[!] Failed to fetch {page_url}: {e}{Style.RESET_ALL}")
            return js_urls

        # Parse HTML for script tags
        soup = BeautifulSoup(content, "html.parser")
        for tag in soup.find_all("script", src=True):
            src = tag["src"].strip()
            full = urljoin(page_url, src)
            if self._is_external_js(full, target_domain):
                skipped.add(urlparse(full).hostname)
            else:
                js_urls.add(full)

        # Regex fallback for dynamically referenced JS
        for pattern in JS_LINK_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                src = match.group(1).strip()
                if src.startswith("//"):
                    src = "https:" + src
                # Skip malformed URLs containing HTML/CSS fragments
                if any(c in src for c in '<>{};'):
                    continue
                if len(src) > 500:
                    continue
                full = urljoin(page_url, src)
                if full.endswith(".js") or ".js?" in full:
                    if self._is_external_js(full, target_domain):
                        skipped.add(urlparse(full).hostname)
                    else:
                        js_urls.add(full)

        if skipped:
            print(f"  {Fore.YELLOW}[*] Skipped {len(skipped)} external JS domains: {', '.join(sorted(skipped))}{Style.RESET_ALL}")

        return js_urls


class JSAnalyzer:
    """Analyzes JS content for endpoints, secrets, and sensitive info."""

    def __init__(self, base_url=""):
        self.base_url = base_url
        self._seen_secrets = set()
        self.results = {
            "endpoints": defaultdict(set),
            "secrets": defaultdict(list),
            "sensitive": defaultdict(list),
            "domains": set(),
            "parameters": set(),
            "endpoint_params": defaultdict(lambda: {"method": "", "params": set(), "content_type": ""}),
            "cloud_urls": set(),
        }

    _SVG_CSS_JUNK = re.compile(
        r"(?:"
        r"\d+\.\d+[A-Z]\d|"                    # SVG path commands: 458.521C753
        r"[MLHVCSQTAZ]\d+[\.\d]*\s|"           # SVG M0 L100 etc
        r"^d=[\"']|"                            # SVG d="" attribute
        r"fill-rule|clip-rule|stroke-width|"    # SVG attributes
        r"viewBox|xmlns|fill-opacity|"
        r"currentColor|stroke-linecap|"
        r"flex[-\s]|rounded-|text-\[|bg-\[|"   # Tailwind CSS classes
        r"px-\[|py-\[|mt-\[|mb-\[|"
        r"sm:|md:|lg:|xl:|tiny:|"               # Tailwind breakpoints
        r"__cf_email__|data-cfemail|"           # Cloudflare email obfuscation
        r"fill=[\"'](?:#|none|white|black|rgb)|"# SVG fill attrs
        r"<path\s|<svg\s|<rect\s|<circle\s|"   # SVG tags
        r"<div\s|<span\s|<a\s|<p\s|<h[1-6]\s|" # HTML tags
        r"class=[\"']|className=[\"']"          # HTML/React class attrs
        r")",
        re.IGNORECASE,
    )

    def _is_noise(self, value):
        if len(value) < 3 or len(value) > 2000:
            return True
        lower = value.lower()
        ext = Path(value.split("?")[0]).suffix.lower()
        if ext in FILTERED_EXTENSIONS:
            return True
        if any(fp in lower for fp in FILTERED_PATHS):
            return True
        if re.match(r"^/[a-zA-Z]$", value):
            return True
        if self._SVG_CSS_JUNK.search(value):
            return True
        # Too many dots/digits = SVG coords or encoded garbage, not a real path
        if value.startswith("/") and not value.startswith("//"):
            digit_ratio = sum(c.isdigit() or c == '.' for c in value) / max(len(value), 1)
            if digit_ratio > 0.4:
                return True
            # Paths with uppercase single-letter segments like /M/C/Z = SVG commands
            segments = [s for s in value.split("/") if s]
            if segments and all(re.match(r'^[A-Z]$', s) for s in segments):
                return True
        if value.startswith("http"):
            host = (urlparse(value).hostname or "").lower()
            if not host:
                return True
            tld = host.rsplit(".", 1)[-1] if "." in host else ""
            if not tld or len(tld) > 10 or not re.match(r"^[a-z]{2,10}$", tld):
                return True
            if self._is_noise_domain(host):
                return True
            if any(ns in lower for ns in ("w3.org", "xml", "xhtml", "mathml", "schema.org", "ogp.me", "purl.org", "rdfs.org")):
                return True
        return False

    @staticmethod
    def _is_noise_domain(domain):
        dl = domain.lower()
        for ext_dom in NOISE_DOMAINS:
            if dl == ext_dom or dl.endswith("." + ext_dom):
                return True
        for nd in NOISE_DOMAINS:
            if dl == nd or dl.endswith("." + nd):
                return True
        if any(ns in dl for ns in ("w3.org", "schema.org", "xml")):
            return True
        return False

    def extract_endpoints(self, content, source=""):
        endpoints = set()
        for pattern in ENDPOINT_PATTERNS:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                val = match.group(1).strip()
                if self._is_noise(val) or not self._is_valid_endpoint(val):
                    continue
                endpoints.add(val)
                self.results["endpoints"][source].add(val)

                if "?" in val:
                    params = re.findall(r"[?&]([a-zA-Z0-9_\-]+)=", val)
                    self.results["parameters"].update(params)

                if val.startswith("http"):
                    parsed = urlparse(val)
                    if parsed.hostname:
                        self.results["domains"].add(parsed.hostname)

        return endpoints

    _PASSWORD_JUNK = re.compile(
        r"^(?:password|passwd|pwd|secret|undefined|null|true|false|none|"
        r"test|admin|example|change.?me|placeholder|\.\*|%filtered%|"
        r"_\w+_\d+)$|"
        r"\.concat\(|encodeURI|[\"']\s*\+\s*\w|"
        r"\+\s*[\"']|\+\s*[a-z]\.|[a-z]\.\w+\s*\+",
        re.IGNORECASE,
    )
    _URL_NOISE_HOSTS = re.compile(r"fonts\.googleapis\.com|googleapis\.com/css|gstatic\.com")

    def extract_secrets(self, content, source=""):
        secrets = []
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.finditer(pattern, content):
                val = match.group(0).strip()
                if len(val) > 500:
                    continue
                inner = match.group(1) if match.lastindex else val
                if name == "Hardcoded Password" and self._PASSWORD_JUNK.search(inner):
                    continue
                if name == "Password in URL" and self._URL_NOISE_HOSTS.search(val):
                    continue
                dedup_key = (name, val)
                if dedup_key in self._seen_secrets:
                    continue
                self._seen_secrets.add(dedup_key)
                line_num = content[:match.start()].count("\n") + 1
                entry = {"type": name, "value": val, "line": line_num, "source": source}
                secrets.append(entry)
                self.results["secrets"][name].append(entry)
                if name in ("S3 Bucket", "S3 Bucket Path", "Azure Storage", "GCP Bucket"):
                    self.results["cloud_urls"].add(val)
        return secrets

    def extract_sensitive(self, content, source=""):
        findings = []
        for name, pattern in SENSITIVE_INFO_PATTERNS.items():
            for match in re.finditer(pattern, content):
                val = match.group(0).strip()
                # Filter noise from sensitive URL matches
                if "URL" in name:
                    host = (urlparse(val).hostname or "").lower()
                    if self._is_noise_domain(host):
                        continue
                line_num = content[:match.start()].count("\n") + 1
                entry = {"type": name, "value": val, "line": line_num, "source": source}
                findings.append(entry)
                self.results["sensitive"][name].append(entry)

        return findings

    _NOISE_WORDS = frozenset({
        "true", "false", "null", "undefined", "function", "return", "const",
        "var", "let", "this", "self", "new", "class", "type", "value",
        "data", "error", "then", "catch", "async", "await", "export",
        "import", "default", "module", "require", "prototype", "length",
        "index", "push", "map", "filter", "reduce", "forEach", "key",
        "method", "headers", "body", "mode", "cache", "credentials",
        "redirect", "referrer", "integrity", "signal", "window", "document",
        "Object", "Array", "String", "Number", "Boolean", "stringify",
        "parse", "apply", "call", "bind", "console", "log", "warn",
    })

    _JUNK_RE = re.compile(r"[=!<>&|(){}\[\];,\^~+]|typeof|void|throw|break|switch|case")

    def _is_valid_endpoint(self, s):
        """Strict check: must look like a real URL path, not minified JS garbage."""
        s = s.strip()
        if len(s) < 2 or len(s) > 500:
            return False
        if self._JUNK_RE.search(s):
            return False
        if not (s.startswith("/") or s.startswith("http://") or s.startswith("https://")):
            return False
        if not re.match(r"^(?:https?://[a-zA-Z0-9\-\.]+)?/[a-zA-Z0-9]", s):
            return False
        # Anchor-only links like /#about are not API endpoints
        if re.match(r'^/#[a-zA-Z0-9_-]+$', s):
            return False
        # Ultra-short paths like /a/b or /x/y — minified JS variable refs
        path_only = s.split("?")[0].split("#")[0]
        segments = [seg for seg in path_only.split("/") if seg]
        if segments and all(len(seg) <= 2 for seg in segments):
            return False
        return True

    def _is_valid_param(self, p):
        if len(p) < 2 or len(p) > 40:
            return False
        if p in self._NOISE_WORDS:
            return False
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9_\-]*$", p):
            return False
        return True

    def _extract_keys(self, raw):
        keys = set()
        for k in re.findall(r"""["']([a-zA-Z_][a-zA-Z0-9_]{1,30})["']\s*:""", raw):
            if self._is_valid_param(k):
                keys.add(k)
        return keys

    def _add_ep_params(self, endpoint, method, params, content_type=""):
        if not self._is_valid_endpoint(endpoint):
            return
        params = {p for p in params if self._is_valid_param(p)}
        if not params:
            return
        if "?" in endpoint:
            endpoint = endpoint.split("?")[0]
        entry = self.results["endpoint_params"][endpoint]
        entry["method"] = method
        entry["params"].update(params)
        if content_type:
            entry["content_type"] = content_type
        self.results["parameters"].update(params)

    def extract_endpoint_params(self, content, source=""):
        # 1) fetch("/path", { ... }) — grab a wide window after the URL
        for m in re.finditer(
            r"""fetch\s*\(\s*["'`](\/[a-zA-Z0-9_/\-\.?&=%]+)["'`]""",
            content
        ):
            endpoint = m.group(1).strip()
            if not self._is_valid_endpoint(endpoint.split("?")[0]):
                continue
            opts = content[m.end():m.end() + 1500]
            # Find the closing ); to scope the options
            depth = 1
            cut = len(opts)
            for i, ch in enumerate(opts):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth <= 0:
                        cut = i
                        break
            opts = opts[:cut]

            method = "GET"
            mm = re.search(r"""method\s*:\s*["'](\w+)["']""", opts, re.IGNORECASE)
            if mm:
                method = mm.group(1).upper()
            body_m = re.search(r"""(?:body|data)\s*:\s*(?:JSON\.stringify\s*\()?\s*\{(["'][a-zA-Z].{2,500})""", opts)
            params = set()
            ct = ""
            if body_m:
                params = self._extract_keys(body_m.group(1))
                ct_m = re.search(r"""["']Content-Type["']\s*:\s*["']([^"']+)["']""", opts)
                ct = ct_m.group(1) if ct_m else "application/json"
            if "?" in endpoint:
                params.update(re.findall(r"[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,30})=", endpoint))
            self._add_ep_params(endpoint, method, params, ct)

        # 2) axios.post("/path", { key: val })
        for m in re.finditer(
            r"""axios\.(get|post|put|delete|patch)\s*\(\s*["'`](\/[^"'`]+)["'`]\s*(?:,\s*\{([^}]{3,500})\})?""",
            content, re.IGNORECASE
        ):
            method = m.group(1).upper()
            endpoint = m.group(2).strip()
            body = m.group(3) or ""
            params = self._extract_keys(body) if body else set()
            if "?" in endpoint:
                params.update(re.findall(r"[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,30})=", endpoint))
            ct = "application/json" if params and method != "GET" else ""
            self._add_ep_params(endpoint, method, params, ct)

        # 3) $.ajax({ url: "/path", type: "POST", data: {...} })
        for m in re.finditer(
            r"""\$\.ajax\s*\(\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}""",
            content
        ):
            block = m.group(1)
            url_m = re.search(r"""url\s*:\s*["'`](\/[^"'`]+)["'`]""", block)
            if not url_m:
                continue
            endpoint = url_m.group(1).strip()
            type_m = re.search(r"""type\s*:\s*["'](\w+)["']""", block, re.IGNORECASE)
            method = type_m.group(1).upper() if type_m else "GET"
            data_m = re.search(r"""data\s*:\s*\{([^}]{3,500})\}""", block)
            params = self._extract_keys(data_m.group(1)) if data_m else set()
            if "?" in endpoint:
                params.update(re.findall(r"[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,30})=", endpoint))
            self._add_ep_params(endpoint, method, params, "application/json" if params else "")

        # 4) XMLHttpRequest: .open("POST", "/path") ... .send({...})
        for m in re.finditer(
            r"""\.open\s*\(\s*["'](\w+)["']\s*,\s*["'`](\/[^"'`]+)["'`]""",
            content
        ):
            method = m.group(1).upper()
            endpoint = m.group(2).strip()
            after = content[m.end():m.end() + 500]
            send_m = re.search(r"""\.send\s*\(\s*(?:JSON\.stringify\s*\()?\s*\{([^}]{3,500})\}""", after)
            params = self._extract_keys(send_m.group(1)) if send_m else set()
            if "?" in endpoint:
                params.update(re.findall(r"[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,30})=", endpoint))
            self._add_ep_params(endpoint, method, params, "application/json" if params else "")

        # 5) FormData.append("key", ...) — scope to nearby fetch
        form_blocks = list(re.finditer(
            r"""((?:\w+\.append\s*\(\s*["'][a-zA-Z][a-zA-Z0-9_\-]*["'][^)]*\)\s*[;\n]\s*){2,})""",
            content
        ))
        for block in form_blocks:
            fields = set(re.findall(r"""\.append\s*\(\s*["']([a-zA-Z][a-zA-Z0-9_\-]+)["']""", block.group(0)))
            if not fields:
                continue
            after = content[block.end():block.end() + 500]
            fm = re.search(r"""(?:fetch|axios\.\w+|\.open)\s*\(\s*["'`](\/[^"'`]+)["'`]""", after)
            key = fm.group(1).split("?")[0] if fm and self._is_valid_endpoint(fm.group(1)) else "[FormData]"
            self._add_ep_params(key, "POST", fields, "multipart/form-data")

        # 6) GraphQL variables: $varName: Type
        gql_vars = set()
        for m in re.finditer(r"""\$([a-zA-Z_][a-zA-Z0-9_]{1,30})\s*:\s*(?:String|Int|Float|Boolean|ID|Input|\[)""", content):
            gql_vars.add(m.group(1))
        if gql_vars:
            gm = re.search(r"""["'`](\/graphql[^"'`]*)["'`]""", content)
            key = gm.group(1) if gm else "/graphql"
            self._add_ep_params(key, "POST", gql_vars, "application/json")

        # 7) Clean query string URLs in quoted strings — strict: must start with /
        for m in re.finditer(r"""["'`](\/[a-zA-Z0-9_/\-]+\?[a-zA-Z][a-zA-Z0-9_\-]{1,}=[^"'`]{0,200})["'`]""", content):
            url_str = m.group(1)
            if self._JUNK_RE.search(url_str):
                continue
            qparams = re.findall(r"[?&]([a-zA-Z][a-zA-Z0-9_\-]{1,30})=", url_str)
            path = url_str.split("?")[0]
            if qparams and self._is_valid_endpoint(path):
                self._add_ep_params(path, "GET", set(qparams))

    _STRIP_SVG_RE = re.compile(r'<svg[\s\S]*?</svg>', re.IGNORECASE)
    _STRIP_STYLE_RE = re.compile(r'<style[\s\S]*?</style>', re.IGNORECASE)
    _STRIP_HTML_TAGS_RE = re.compile(
        r'<(?:div|span|section|footer|header|nav|main|aside|article|form|'
        r'label|button|input|textarea|select|option|table|tr|td|th|thead|'
        r'tbody|ul|ol|li|dl|dt|dd|figure|figcaption|picture|source|video|'
        r'audio|canvas|details|summary|dialog|address|blockquote|'
        r'path|rect|circle|ellipse|line|polygon|polyline|g|defs|use|symbol|'
        r'clipPath|linearGradient|radialGradient|stop|mask|pattern|image|'
        r'foreignObject|text|tspan)\b[^>]*>',
        re.IGNORECASE,
    )

    _STRIP_NEXTDATA_RE = re.compile(
        r'<script\s+id="__NEXT_DATA__"[^>]*>[\s\S]*?</script>', re.IGNORECASE
    )
    _STRIP_SVG_DATTR_RE = re.compile(r'\bd="[MLHVCSQTAZ0-9\.\s,\-]+"', re.IGNORECASE)

    @staticmethod
    def _clean_content(content):
        """Strip SVG, <style> blocks, Next.js data, and raw HTML tags to avoid garbage matches."""
        content = JSAnalyzer._STRIP_NEXTDATA_RE.sub('', content)
        content = JSAnalyzer._STRIP_SVG_RE.sub('', content)
        content = JSAnalyzer._STRIP_STYLE_RE.sub('', content)
        content = JSAnalyzer._STRIP_SVG_DATTR_RE.sub('', content)
        content = JSAnalyzer._STRIP_HTML_TAGS_RE.sub('', content)
        return content

    def extract_all(self, content, source=""):
        content = self._clean_content(content)
        self.extract_endpoints(content, source)
        self.extract_secrets(content, source)
        self.extract_sensitive(content, source)
        self.extract_endpoint_params(content, source)


class TargetAnalyzer:
    """Analyzes target URL for security headers, cookies, CORS, tech stack."""

    def __init__(self, fetcher):
        self.fetcher = fetcher
        self.results = {
            "tech": set(),
            "missing_headers": [],
            "weak_headers": [],
            "info_leaks": [],
            "cookies": [],
            "cors": {},
            "dangerous_methods": [],
        }

    def analyze(self, url):
        try:
            resp = self.fetcher.session.get(url, timeout=self.fetcher.timeout, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            print(f"  {Fore.RED}[!] Target analysis failed: {e}{Style.RESET_ALL}")
            return self.results

        headers = resp.headers

        # Missing security headers
        lower_headers = {k.lower() for k in headers}
        for hdr, (severity, desc) in SECURITY_HEADERS_CHECK.items():
            if hdr not in lower_headers:
                self.results["missing_headers"].append({"header": hdr, "severity": severity, "description": desc})

        # Weak CSP
        csp = headers.get("content-security-policy", "")
        if csp:
            for check, msg in [("unsafe-inline", "allows unsafe-inline"), ("unsafe-eval", "allows unsafe-eval"), ("*", "wildcard source")]:
                if check in csp:
                    self.results["weak_headers"].append({"header": "CSP", "severity": "MEDIUM", "issue": msg})

        # Info leak headers
        for hdr in INFO_LEAK_HEADERS:
            val = headers.get(hdr)
            if val:
                self.results["info_leaks"].append({"header": hdr, "value": val})

        # Tech fingerprint
        for hdr_name, sigs in TECH_SIGNATURES.items():
            val = headers.get(hdr_name, "").lower()
            for keyword, tech in sigs.items():
                if keyword in val:
                    self.results["tech"].add(tech)
        if headers.get("cf-ray"):
            self.results["tech"].add("Cloudflare")
        if headers.get("x-amzn-requestid") or headers.get("x-amz-cf-id"):
            self.results["tech"].add("AWS")
        if headers.get("x-vercel-id"):
            self.results["tech"].add("Vercel")

        # CORS
        acao = headers.get("access-control-allow-origin", "")
        if acao:
            self.results["cors"] = {
                "allow_origin": acao,
                "allow_credentials": headers.get("access-control-allow-credentials", ""),
                "allow_methods": headers.get("access-control-allow-methods", ""),
            }
            if acao == "*":
                self.results["weak_headers"].append({"header": "CORS", "severity": "MEDIUM", "issue": "Origin=* (any site can read responses)"})
            if acao == "*" and headers.get("access-control-allow-credentials", "") == "true":
                self.results["weak_headers"].append({"header": "CORS", "severity": "HIGH", "issue": "Origin=* + credentials=true — full CORS bypass"})

        # CORS reflection test
        for evil in ["https://evil.com", "null"]:
            try:
                r2 = self.fetcher.session.get(url, timeout=self.fetcher.timeout, verify=False, headers={"Origin": evil})
                reflected = r2.headers.get("access-control-allow-origin", "")
                if reflected == evil:
                    sev = "HIGH" if r2.headers.get("access-control-allow-credentials") == "true" else "MEDIUM"
                    self.results["weak_headers"].append({"header": "CORS", "severity": sev, "issue": f"Origin reflected: '{evil}' -> '{reflected}'" + (" + credentials!" if sev == "HIGH" else "")})
            except requests.RequestException:
                pass

        # Cookie analysis
        for cookie_hdr in resp.headers.getlist("set-cookie") if hasattr(resp.headers, "getlist") else [resp.headers.get("set-cookie", "")]:
            if not cookie_hdr:
                continue
            for cookie_str in cookie_hdr.split("\n"):
                cookie_str = cookie_str.strip()
                if not cookie_str:
                    continue
                parts = cookie_str.split(";")
                name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
                flags = {p.strip().lower().split("=")[0] for p in parts[1:]}
                issues = []
                if url.startswith("https") and "secure" not in flags:
                    issues.append("no Secure")
                if "httponly" not in flags:
                    issues.append("no HttpOnly")
                if not any("samesite" in f for f in flags):
                    issues.append("no SameSite")
                if issues:
                    self.results["cookies"].append({"name": name, "issues": issues})

        # Dangerous HTTP methods
        for method in ["TRACE", "PUT", "DELETE"]:
            try:
                r3 = self.fetcher.session.request(method, url, timeout=self.fetcher.timeout, verify=False)
                if r3.status_code not in (405, 501, 400, 403, 404, 301, 302, 307, 308):
                    self.results["dangerous_methods"].append({"method": method, "status": r3.status_code, "url": url})
            except requests.RequestException:
                pass

        return self.results

    def print_results(self):
        r = self.results
        has_output = False

        if r["tech"]:
            has_output = True
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f" TECHNOLOGY STACK")
            print(f"{'='*60}{Style.RESET_ALL}")
            for t in sorted(r["tech"]):
                print(f"    {Fore.YELLOW}{t}{Style.RESET_ALL}")

        if r["info_leaks"]:
            has_output = True
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f" SERVER INFO LEAKS")
            print(f"{'='*60}{Style.RESET_ALL}")
            for leak in r["info_leaks"]:
                print(f"    {leak['header']}: {Fore.YELLOW}{leak['value']}{Style.RESET_ALL}")

        if r["missing_headers"]:
            has_output = True
            print(f"\n{Fore.RED}{'='*60}")
            print(f" MISSING SECURITY HEADERS ({len(r['missing_headers'])})")
            print(f"{'='*60}{Style.RESET_ALL}")
            order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
            for m in sorted(r["missing_headers"], key=lambda x: order[x["severity"]]):
                c = {Fore.RED: "HIGH", Fore.YELLOW: "MEDIUM", Fore.CYAN: "LOW"}
                scolor = Fore.RED if m["severity"] == "HIGH" else Fore.YELLOW if m["severity"] == "MEDIUM" else Fore.CYAN
                print(f"    {scolor}[{m['severity']}]{Style.RESET_ALL} {m['header']} — {m['description']}")

        if r["weak_headers"]:
            has_output = True
            print(f"\n{Fore.RED}{'='*60}")
            print(f" WEAK / MISCONFIGURED ({len(r['weak_headers'])})")
            print(f"{'='*60}{Style.RESET_ALL}")
            for w in r["weak_headers"]:
                scolor = Fore.RED if w["severity"] == "HIGH" else Fore.YELLOW if w["severity"] == "MEDIUM" else Fore.CYAN
                print(f"    {scolor}[{w['severity']}]{Style.RESET_ALL} {w['header']}: {w['issue']}")

        if r["cors"]:
            has_output = True
            print(f"\n{Fore.CYAN}{'='*60}")
            print(f" CORS CONFIGURATION")
            print(f"{'='*60}{Style.RESET_ALL}")
            for k, v in r["cors"].items():
                if v:
                    print(f"    {k}: {v}")

        if r["cookies"]:
            has_output = True
            print(f"\n{Fore.MAGENTA}{'='*60}")
            print(f" COOKIE ISSUES")
            print(f"{'='*60}{Style.RESET_ALL}")
            for c in r["cookies"]:
                print(f"    {Fore.WHITE}{c['name']}{Style.RESET_ALL}: {Fore.RED}{', '.join(c['issues'])}{Style.RESET_ALL}")

        if r["dangerous_methods"]:
            has_output = True
            print(f"\n{Fore.RED}{'='*60}")
            print(f" DANGEROUS HTTP METHODS")
            print(f"{'='*60}{Style.RESET_ALL}")
            for dm in r["dangerous_methods"]:
                url_label = dm.get('url', '?')
                print(f"    {Fore.RED}{dm['method']}{Style.RESET_ALL} -> {dm['status']}  {Fore.WHITE}@ {url_label}{Style.RESET_ALL}")

        if not has_output:
            print(f"\n{Fore.GREEN}[+] Target headers look clean{Style.RESET_ALL}")


class SubdomainCollector:
    """Enumerates subdomains from multiple passive sources and checks which are alive."""

    def __init__(self, fetcher, threads=20):
        self.fetcher = fetcher
        self.threads = threads
        self.subdomains = set()
        self.alive = []  # list of {"subdomain", "url", "status", "title", "server", "redirect"}

    def _add_subs(self, domain, raw_list):
        for sub in raw_list:
            sub = sub.strip().lower()
            if not sub or "*" in sub or " " in sub or len(sub) > 200:
                continue
            if sub == domain or sub.endswith("." + domain):
                self.subdomains.add(sub)

    def from_crtsh(self, domain):
        print(f"    {Fore.CYAN}[crt.sh]{Style.RESET_ALL} ", end="", flush=True)
        try:
            resp = self.fetcher.session.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=25, verify=False,
            )
            if resp.status_code == 200:
                names = []
                for entry in resp.json():
                    val = entry.get("name_value", "")
                    names.extend(val.split("\n"))
                self._add_subs(domain, names)
                print(f"{len(names)} certs parsed")
            else:
                print(f"status {resp.status_code}")
        except Exception as e:
            print(f"failed: {e}")

    def from_hackertarget(self, domain):
        print(f"    {Fore.CYAN}[hackertarget]{Style.RESET_ALL} ", end="", flush=True)
        try:
            resp = self.fetcher.session.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                timeout=15, verify=False,
            )
            if resp.status_code == 200 and "error" not in resp.text.lower():
                subs = [line.split(",")[0] for line in resp.text.strip().split("\n") if "," in line]
                self._add_subs(domain, subs)
                print(f"{len(subs)} found")
            else:
                print("no results")
        except Exception as e:
            print(f"failed: {e}")

    def from_rapiddns(self, domain):
        print(f"    {Fore.CYAN}[rapiddns]{Style.RESET_ALL} ", end="", flush=True)
        try:
            resp = self.fetcher.session.get(
                f"https://rapiddns.io/subdomain/{domain}?full=1",
                timeout=15, verify=False,
            )
            if resp.status_code == 200:
                subs = re.findall(r"<td>([a-zA-Z0-9\.\-]+\." + re.escape(domain) + r")</td>", resp.text)
                self._add_subs(domain, subs)
                print(f"{len(subs)} found")
            else:
                print("no results")
        except Exception as e:
            print(f"failed: {e}")

    def from_urlscan(self, domain):
        print(f"    {Fore.CYAN}[urlscan.io]{Style.RESET_ALL} ", end="", flush=True)
        try:
            resp = self.fetcher.session.get(
                f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000",
                timeout=15, verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    d = page.get("domain", "")
                    if d:
                        subs.add(d)
                self._add_subs(domain, subs)
                print(f"{len(subs)} found")
            else:
                print("no results")
        except Exception as e:
            print(f"failed: {e}")

    def from_otx(self, domain):
        print(f"    {Fore.CYAN}[AlienVault OTX]{Style.RESET_ALL} ", end="", flush=True)
        try:
            resp = self.fetcher.session.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                timeout=15, verify=False,
            )
            if resp.status_code == 200:
                data = resp.json()
                subs = [entry.get("hostname", "") for entry in data.get("passive_dns", [])]
                self._add_subs(domain, subs)
                print(f"{len(subs)} found")
            else:
                print("no results")
        except Exception as e:
            print(f"failed: {e}")

    def from_domains(self, domains, base_domain):
        for d in domains:
            d = d.lower()
            if d.endswith(base_domain):
                self.subdomains.add(d)

    def enumerate(self, domain):
        """Run all passive enumeration sources."""
        self.from_crtsh(domain)
        self.from_hackertarget(domain)
        self.from_rapiddns(domain)
        self.from_urlscan(domain)
        self.from_otx(domain)

    WEB_PORTS = [
        (443, "https"), (80, "http"),
        (8443, "https"), (8080, "http"), (8000, "http"), (8888, "http"),
        (3000, "http"), (3443, "https"), (4443, "https"),
        (5000, "http"), (5443, "https"),
        (9443, "https"), (9090, "http"), (9000, "http"),
        (8081, "http"), (8082, "http"), (8181, "http"),
        (443, "https"), (4000, "http"), (7443, "https"),
        (10443, "https"), (2087, "https"), (2083, "https"),
        (10000, "http"),
    ]

    def _probe_url(self, url):
        try:
            resp = self.fetcher.session.get(
                url, timeout=4, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            title = ""
            title_m = re.search(r"<title[^>]*>([^<]{1,100})</title>", resp.text, re.IGNORECASE)
            if title_m:
                title = title_m.group(1).strip()
            redirect = resp.url if resp.history else ""
            return {
                "url": url,
                "status": resp.status_code,
                "title": title,
                "server": resp.headers.get("server", ""),
                "redirect": redirect,
                "content_length": len(resp.content),
            }
        except requests.RequestException:
            return None

    def _probe_single(self, subdomain, port, scheme, use_port_in_url=True):
        """Probe one subdomain:port combo."""
        if use_port_in_url:
            url = f"{scheme}://{subdomain}:{port}"
        else:
            url = f"{scheme}://{subdomain}"
        r = self._probe_url(url)
        if r:
            r["subdomain"] = subdomain
            r["port"] = port
        return r

    @staticmethod
    def _format_alive(s):
        sc = s["status"]
        if 200 <= sc < 300:
            sc_str = f"{Fore.GREEN}{sc}{Style.RESET_ALL}"
        elif 300 <= sc < 400:
            sc_str = f"{Fore.YELLOW}{sc}{Style.RESET_ALL}"
        elif 400 <= sc < 500:
            sc_str = f"{Fore.RED}{sc}{Style.RESET_ALL}"
        else:
            sc_str = f"{Fore.MAGENTA}{sc}{Style.RESET_ALL}"
        title_str = f" [{s['title'][:40]}]" if s["title"] else ""
        server_str = f" ({s['server']})" if s["server"] else ""
        redir_str = f" -> {s['redirect']}" if s["redirect"] else ""
        return f"    {sc_str} {s['url']}{title_str}{server_str}{redir_str}"

    def check_alive(self):
        """Probe all subdomains on default + common web ports concurrently."""
        if not self.subdomains:
            return

        targets = sorted(self.subdomains)
        seen_ports = set()
        extra_ports_list = []
        for port, scheme in self.WEB_PORTS:
            if port not in seen_ports and port not in (80, 443):
                seen_ports.add(port)
                extra_ports_list.append((port, scheme))

        print(f"\n{Fore.CYAN}[*] Checking {len(targets)} subdomains alive (ports: 80,443 + {len(extra_ports_list)} common web ports)...{Style.RESET_ALL}")

        jobs = []
        for sub in targets:
            jobs.append((sub, 443, "https", False))
            jobs.append((sub, 80, "http", False))
            for port, scheme in extra_ports_list:
                jobs.append((sub, port, scheme, True))

        workers = min(len(jobs), max(self.threads * 5, 50))
        raw_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self._probe_single, s, p, sc, u): (s, p) for s, p, sc, u in jobs}
            for future in concurrent.futures.as_completed(futures):
                r = future.result()
                if r:
                    raw_results.append(r)

        seen = {}
        for r in sorted(raw_results, key=lambda x: (x["subdomain"], x["port"])):
            final_url = r.get("redirect") or r["url"]
            final_url = re.sub(r"/$", "", final_url.split("?")[0])
            key = (r["subdomain"], r["status"], final_url, r["title"])
            if key not in seen:
                seen[key] = r
            elif r["url"].startswith("https://") and r["port"] in (443, 8443):
                seen[key] = r

        self.alive = list(seen.values())
        self.alive.sort(key=lambda x: (x["subdomain"], x["port"]))
        for r in self.alive:
            print(self._format_alive(r))

    def _resolve_one(self, subdomain):
        ips = set()
        try:
            for info in socket.getaddrinfo(subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                ips.add(info[4][0])
        except (socket.gaierror, OSError):
            pass
        return subdomain, ips

    def resolve_ips(self):
        """Resolve all subdomains to IPs concurrently."""
        if not self.subdomains:
            return
        self.ip_map = {}
        self.ip_to_subs = defaultdict(list)
        targets = sorted(self.subdomains)
        print(f"\n{Fore.CYAN}[*] Resolving IPs for {len(targets)} subdomains...{Style.RESET_ALL}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._resolve_one, s): s for s in targets}
            for f in concurrent.futures.as_completed(futures):
                sub, ips = f.result()
                if ips:
                    self.ip_map[sub] = ips
                    for ip in ips:
                        self.ip_to_subs[ip].append(sub)

    def print_results(self):
        if not self.subdomains:
            return

        print(f"\n{Fore.BLUE}{'='*60}")
        print(f" SUBDOMAINS ({len(self.subdomains)} found)")
        print(f"{'='*60}{Style.RESET_ALL}")
        for s in sorted(self.subdomains):
            is_alive = any(a["subdomain"] == s for a in self.alive)
            marker = f"{Fore.GREEN}[LIVE]{Style.RESET_ALL} " if is_alive else f"{Fore.RED}[DEAD]{Style.RESET_ALL} "
            ip_str = ""
            if hasattr(self, "ip_map") and s in self.ip_map:
                ip_str = f" {Fore.YELLOW}[{', '.join(sorted(self.ip_map[s]))}]{Style.RESET_ALL}"
            print(f"    {marker}{s}{ip_str}")

        if self.alive:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f" ALIVE TARGETS ({len(self.alive)} live)")
            print(f"{'='*60}{Style.RESET_ALL}")
            for a in self.alive:
                print(self._format_alive(a))

        if hasattr(self, "ip_to_subs") and self.ip_to_subs:
            unique_ips = sorted(self.ip_to_subs.keys(), key=lambda ip: (not ip.replace(".", "").isdigit(), ip))
            print(f"\n{Fore.MAGENTA}{'='*60}")
            print(f" IP ADDRESS POOL ({len(unique_ips)} unique IPs)")
            print(f"{'='*60}{Style.RESET_ALL}")
            cdn_ips = set()
            direct_ips = set()
            for ip in unique_ips:
                subs = sorted(self.ip_to_subs[ip])
                count = len(subs)
                if count > 10:
                    cdn_ips.add(ip)
                    print(f"    {Fore.YELLOW}{ip}{Style.RESET_ALL} [{count} subs] (likely CDN/WAF)")
                    print(f"      {', '.join(subs[:5])}{'...' if count > 5 else ''}")
                else:
                    direct_ips.add(ip)
                    for sub in subs:
                        is_alive = any(a["subdomain"] == sub for a in self.alive)
                        status = f"{Fore.GREEN}LIVE{Style.RESET_ALL}" if is_alive else f"{Fore.RED}DEAD{Style.RESET_ALL}"
                        print(f"    {Fore.CYAN}{ip:>39}{Style.RESET_ALL}  {sub} [{status}]")
            if cdn_ips and direct_ips:
                print(f"\n    {Fore.GREEN}[+] {len(direct_ips)} direct IPs, {len(cdn_ips)} CDN/shared IPs{Style.RESET_ALL}")

    def save_alive(self, output_path):
        if not self.alive:
            return
        with open(output_path, "w") as f:
            for a in self.alive:
                f.write(a["url"] + "\n")
        print(f"{Fore.GREEN}[+] Alive URLs saved to: {output_path}{Style.RESET_ALL}")

    def save_subs(self, output_path):
        if not self.subdomains:
            return
        with open(output_path, "w") as f:
            for s in sorted(self.subdomains):
                f.write(s + "\n")
        print(f"{Fore.GREEN}[+] Subdomains saved to: {output_path}{Style.RESET_ALL}")


class APIFuzzer:
    """Fuzz alive hosts with common API/admin/debug paths."""

    FUZZ_PATHS = [
        # API docs
        "/swagger/", "/swagger-ui/", "/swagger-ui.html", "/swagger.json",
        "/api-docs", "/api-docs/", "/openapi.json", "/openapi.yaml",
        "/redoc", "/docs", "/docs/", "/api/docs",
        # GraphQL
        "/graphql", "/graphiql", "/graphql/console", "/v1/graphql",
        "/api/graphql", "/gql",
        # Common API bases
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/rest/", "/v1/", "/v2/",
        "/api/health", "/api/status", "/api/info", "/api/version",
        "/health", "/healthz", "/ready", "/status", "/ping", "/info",
        # Admin / management
        "/admin/", "/admin/login", "/administrator/",
        "/manager/", "/manager/html",
        "/wp-admin/", "/wp-login.php",
        "/cpanel", "/plesk",
        "/dashboard/", "/portal/",
        # Debug / dev
        "/debug/", "/debug/vars", "/debug/pprof/",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/beans", "/actuator/mappings", "/actuator/configprops",
        "/.env", "/.env.local", "/.env.production",
        "/config", "/config.json", "/config.js", "/app-config.json",
        "/server-info", "/server-status",
        "/phpinfo.php", "/info.php",
        "/elmah.axd", "/trace.axd",
        "/_debug", "/_profiler",
        # Auth endpoints
        "/login", "/auth/login", "/api/login", "/api/auth",
        "/oauth/token", "/oauth/authorize",
        "/token", "/auth/token", "/api/token",
        "/register", "/signup", "/api/register",
        "/forgot-password", "/reset-password",
        "/.well-known/openid-configuration",
        "/realms/master/.well-known/openid-configuration",
        # User/data endpoints
        "/api/users", "/api/v1/users", "/api/user", "/api/me",
        "/api/profile", "/api/accounts",
        "/users", "/users/", "/accounts",
        # Files / uploads
        "/upload", "/uploads/", "/files/", "/media/",
        "/api/upload", "/api/files",
        # Source / git
        "/.git/HEAD", "/.git/config",
        "/.svn/entries", "/.hg/",
        "/.DS_Store", "/Thumbs.db",
        "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
        "/security.txt", "/.well-known/security.txt",
        # Backup / sensitive files
        "/backup/", "/backups/", "/dump/",
        "/db/", "/database/",
        "/web.config", "/wp-config.php.bak",
        "/.htaccess", "/.htpasswd",
        "/composer.json", "/package.json",
        "/Dockerfile", "/docker-compose.yml",
        # Cloud metadata
        "/latest/meta-data/",
        # Websocket / realtime
        "/ws", "/wss", "/socket.io/", "/sockjs/",
        "/hub", "/signalr/",
    ]

    INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503}

    def __init__(self, fetcher, threads=30):
        self.fetcher = fetcher
        self.threads = threads
        self.results = []

    def _fuzz_one(self, base_url, path):
        url = base_url.rstrip("/") + path
        try:
            resp = self.fetcher.session.get(
                url, timeout=4, verify=False, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
            )
            sc = resp.status_code
            if sc == 404:
                return None
            clen = len(resp.content)
            if clen < 5:
                return None
            body_start = resp.text[:1000]
            if any(x in body_start for x in ("Request Rejected", "Attention Required", "Just a moment", "cf-error")):
                return None
            if sc == 403 and clen < 300 and any(x in body_start for x in ("403 Forbidden", "Access denied", "Forbidden")):
                return None
            if sc in (502, 503, 521) and any(x in body_start for x in ("Service Unavailable", "Service Temporarily", "Temporarily Unavailable", "Bad gateway", "Web server is down", "cf-error")):
                return None
            title = ""
            tm = re.search(r"<title[^>]*>([^<]{1,80})</title>", resp.text, re.IGNORECASE)
            if tm:
                title = tm.group(1).strip()
            ct = resp.headers.get("Content-Type", "")
            server = resp.headers.get("Server", "")
            redir = resp.url if resp.history else ""
            return {
                "path": path,
                "url": url,
                "status": sc,
                "size": clen,
                "title": title,
                "content_type": ct,
                "server": server,
                "redirect": redir,
            }
        except requests.RequestException:
            return None

    def _detect_wildcard(self, base_url):
        """Send a request to a random path to detect wildcard/soft-404 responses."""
        rand_path = f"/{''.join(random.choices('abcdefghijklmnop', k=12))}_404test"
        r = self._fuzz_one(base_url, rand_path)
        if r:
            return r["status"], r["size"], r["title"]
        return None, None, None

    def fuzz_host(self, base_url):
        wc_status, wc_size, wc_title = self._detect_wildcard(base_url)
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._fuzz_one, base_url, p): p for p in self.FUZZ_PATHS}
            for f in concurrent.futures.as_completed(futures):
                r = f.result()
                if not r:
                    continue
                if wc_status is not None:
                    if r["status"] == wc_status and abs(r["size"] - wc_size) < 100 and r["title"] == wc_title:
                        continue
                results.append(r)
        return sorted(results, key=lambda x: (x["status"], x["path"]))

    def fuzz_alive(self, alive_list):
        best = {}
        for a in alive_list:
            sub = a["subdomain"]
            sc = a["status"]
            if sc >= 400:
                continue
            port = a["port"]
            is_https_default = a["url"].startswith("https://") and port in (443, 8443)
            if sub not in best or is_https_default:
                best[sub] = a
        targets = []
        seen_bases = set()
        for sub, a in best.items():
            base = re.match(r"(https?://[^/]+)", a["url"])
            base_url = base.group(1) if base else a["url"]
            if base_url in seen_bases:
                continue
            seen_bases.add(base_url)
            targets.append((sub, base_url))

        print(f"\n{Fore.CYAN}[*] API fuzzing {len(targets)} hosts with {len(self.FUZZ_PATHS)} paths...{Style.RESET_ALL}")

        for sub, base_url in sorted(targets):
            hits = self.fuzz_host(base_url)
            if hits:
                self.results.extend(hits)
                for h in hits:
                    self._print_hit(h)

    @staticmethod
    def _print_hit(h):
        sc = h["status"]
        if 200 <= sc < 300:
            sc_str = f"{Fore.GREEN}{sc}{Style.RESET_ALL}"
        elif 300 <= sc < 400:
            sc_str = f"{Fore.YELLOW}{sc}{Style.RESET_ALL}"
        elif sc in (401, 403):
            sc_str = f"{Fore.RED}{sc}{Style.RESET_ALL}"
        else:
            sc_str = f"{Fore.MAGENTA}{sc}{Style.RESET_ALL}"
        size = h["size"]
        ct_short = h["content_type"].split(";")[0] if h["content_type"] else ""
        title = f" [{h['title'][:40]}]" if h["title"] else ""
        redir = f" -> {h['redirect']}" if h["redirect"] else ""
        print(f"    {sc_str} {h['url']} [{size}b] {ct_short}{title}{redir}")

    def print_results(self):
        if not self.results:
            return
        by_category = defaultdict(list)
        for r in self.results:
            p = r["path"]
            if any(x in p for x in ("swagger", "openapi", "api-docs", "redoc", "docs", "graphql", "graphiql", "gql")):
                by_category["API Docs / GraphQL"].append(r)
            elif any(x in p for x in ("actuator", "debug", "pprof", "profiler", "phpinfo", "elmah", "trace", "server-info", "server-status")):
                by_category["Debug / Profiling"].append(r)
            elif any(x in p for x in (".git", ".svn", ".hg", ".DS_Store", ".env", ".htaccess", ".htpasswd", "web.config", "wp-config", "composer.json", "package.json", "Dockerfile", "docker-compose")):
                by_category["Sensitive Files"].append(r)
            elif any(x in p for x in ("admin", "manager", "dashboard", "portal", "cpanel", "plesk", "wp-admin", "wp-login")):
                by_category["Admin Panels"].append(r)
            elif any(x in p for x in ("login", "auth", "oauth", "token", "register", "signup", "forgot", "reset", "openid")):
                by_category["Auth Endpoints"].append(r)
            elif any(x in p for x in ("health", "ready", "status", "ping", "info", "version")):
                by_category["Health / Status"].append(r)
            elif any(x in p for x in ("api/", "rest/", "/v1", "/v2", "/v3", "users", "user", "me", "profile", "accounts")):
                by_category["API Endpoints"].append(r)
            else:
                by_category["Other"].append(r)

        print(f"\n{Fore.RED}{'='*60}")
        print(f" API FUZZ RESULTS ({len(self.results)} hits)")
        print(f"{'='*60}{Style.RESET_ALL}")
        for cat in ("Sensitive Files", "Debug / Profiling", "API Docs / GraphQL", "Admin Panels",
                     "Auth Endpoints", "API Endpoints", "Health / Status", "Other"):
            items = by_category.get(cat, [])
            if not items:
                continue
            print(f"\n  {Fore.YELLOW}[{cat}]{Style.RESET_ALL}")
            for h in items:
                APIFuzzer._print_hit(h)

    def get_json_results(self):
        return self.results


class DeepAnalyzer:
    """Deep analysis: inline JS, webpack chunks, source maps."""

    def __init__(self, fetcher):
        self.fetcher = fetcher

    def find_webpack_chunks(self, content, base_url):
        chunk_urls = set()
        patterns = [
            r"""(?:__webpack_require__|webpackJsonp|push)\s*\(\s*\[.*?\]\s*,\s*\{(.*?)\}""",
            r"""["'](\d+)["']\s*:\s*["']([a-f0-9]{6,})["']""",
            r"""(?:chunkFilename|publicPath)\s*[:=]\s*["']([^"']+)["']""",
            r"""["']static/js/["']\s*\+\s*(?:\{[^}]*\}\[)?[a-z]\]?\s*\+\s*["']\.["']\s*\+\s*\{([^}]+)\}""",
        ]
        for pat in patterns:
            for m in re.finditer(pat, content, re.DOTALL):
                raw = m.group(1) if m.lastindex else m.group(0)
                chunk_ids = re.findall(r"""["']?(\d+)["']?\s*:\s*["']([a-f0-9]{6,20})["']""", raw)
                for cid, chash in chunk_ids:
                    for prefix in ["static/js/", "js/", "chunks/", ""]:
                        chunk_url = urljoin(base_url, f"{prefix}{cid}.{chash}.chunk.js")
                        chunk_urls.add(chunk_url)

        return chunk_urls

    def find_sourcemaps(self, content, base_url):
        maps = set()
        for m in re.finditer(r"//[#@]\s*sourceMappingURL=(\S+)", content):
            url = m.group(1).strip()
            full = urljoin(base_url, url)
            maps.add(full)
        return maps

    def fetch_sourcemap(self, url):
        content = self.fetcher.fetch_url(url)
        if not content:
            return ""
        try:
            data = json.loads(content)
            sources_content = data.get("sourcesContent", [])
            return "\n".join(sources_content)
        except (json.JSONDecodeError, TypeError):
            return ""


class APIProber:
    """Probes discovered endpoints to check accepted HTTP methods, response info, and headers."""

    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    METHOD_COLORS = {
        "GET": Fore.GREEN,
        "POST": Fore.YELLOW,
        "PUT": Fore.BLUE,
        "DELETE": Fore.RED,
        "PATCH": Fore.MAGENTA,
        "OPTIONS": Fore.CYAN,
        "HEAD": Fore.WHITE,
    }

    INTERESTING_HEADERS = [
        "server", "x-powered-by", "x-aspnet-version", "x-runtime",
        "x-framework", "x-generator", "x-debug", "x-request-id",
        "access-control-allow-origin", "access-control-allow-methods",
        "access-control-allow-headers", "access-control-allow-credentials",
        "content-security-policy", "x-content-type-options",
        "strict-transport-security", "www-authenticate",
        "x-ratelimit-limit", "x-ratelimit-remaining",
        "x-amzn-requestid", "x-cloud-trace-context",
        "set-cookie",
    ]

    def __init__(self, fetcher, base_url, threads=5):
        self.fetcher = fetcher
        self.base_url = base_url.rstrip("/")
        self.threads = threads
        self.probe_results = []

    def _resolve_url(self, endpoint):
        if endpoint.startswith("http"):
            return endpoint
        return self.base_url + endpoint

    def _probe_single(self, endpoint):
        url = self._resolve_url(endpoint)
        result = {
            "endpoint": endpoint,
            "url": url,
            "methods": {},
            "interesting_headers": {},
            "tech_hints": set(),
            "cors": {},
            "auth_required": False,
        }

        for method in self.METHODS:
            try:
                resp = self.fetcher.session.request(
                    method, url,
                    timeout=self.fetcher.timeout,
                    verify=False,
                    allow_redirects=False,
                )
                status = resp.status_code
                # Skip if method is clearly not allowed
                if status == 405:
                    continue

                method_info = {
                    "status": status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "content_length": resp.headers.get("Content-Length", "?"),
                }

                # Check for JSON response body (truncated)
                if method in ("GET", "POST") and "json" in method_info["content_type"].lower():
                    try:
                        body = resp.text[:500]
                        method_info["body_preview"] = body
                    except Exception:
                        pass

                result["methods"][method] = method_info

                if status in (401, 403):
                    result["auth_required"] = True

                # Collect interesting headers (only once per endpoint)
                if not result["interesting_headers"]:
                    for hdr in self.INTERESTING_HEADERS:
                        val = resp.headers.get(hdr)
                        if val:
                            result["interesting_headers"][hdr] = val

                    # Tech fingerprinting from headers
                    server = resp.headers.get("server", "")
                    powered = resp.headers.get("x-powered-by", "")
                    if server:
                        result["tech_hints"].add(f"Server: {server}")
                    if powered:
                        result["tech_hints"].add(f"X-Powered-By: {powered}")

                # CORS info from OPTIONS
                if method == "OPTIONS":
                    result["cors"] = {
                        "allow_origin": resp.headers.get("access-control-allow-origin", ""),
                        "allow_methods": resp.headers.get("access-control-allow-methods", ""),
                        "allow_headers": resp.headers.get("access-control-allow-headers", ""),
                        "allow_credentials": resp.headers.get("access-control-allow-credentials", ""),
                    }

            except requests.RequestException:
                continue

        if result["methods"]:
            self.probe_results.append(result)
        return result

    def probe_endpoints(self, endpoints):
        targets = sorted(endpoints)
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PROBING {len(targets)} ENDPOINTS")
        print(f"{'='*60}{Style.RESET_ALL}\n")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe_single, ep): ep for ep in targets}
            for future in concurrent.futures.as_completed(futures):
                ep = futures[future]
                try:
                    result = future.result()
                    if result["methods"]:
                        self._print_probe_result(result)
                except Exception as e:
                    print(f"  {Fore.RED}[!] Error probing {ep}: {e}{Style.RESET_ALL}")

        self._print_probe_summary()

    def _print_probe_result(self, result):
        ep = result["endpoint"]
        methods = result["methods"]

        method_str = ""
        for m, info in sorted(methods.items()):
            color = self.METHOD_COLORS.get(m, Fore.WHITE)
            status = info["status"]
            # Color status codes
            if 200 <= status < 300:
                sc = f"{Fore.GREEN}{status}{Style.RESET_ALL}"
            elif 300 <= status < 400:
                sc = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
            elif 400 <= status < 500:
                sc = f"{Fore.RED}{status}{Style.RESET_ALL}"
            else:
                sc = f"{Fore.MAGENTA}{status}{Style.RESET_ALL}"
            method_str += f" {color}{m}{Style.RESET_ALL}:{sc}"

        print(f"  {Fore.WHITE}{ep}{Style.RESET_ALL}")
        print(f"    Methods:{method_str}")

        # Show content type for GET if available
        get_info = methods.get("GET") or methods.get("POST")
        if get_info:
            ct = get_info.get("content_type", "")
            cl = get_info.get("content_length", "?")
            if ct:
                print(f"    Content: {ct} | Size: {cl}")

        # Body preview
        if get_info and get_info.get("body_preview"):
            preview = get_info["body_preview"][:120].replace("\n", " ")
            print(f"    Preview: {Fore.CYAN}{preview}{Style.RESET_ALL}")

        # Auth required
        if result["auth_required"]:
            print(f"    {Fore.RED}[!] Auth required (401/403){Style.RESET_ALL}")

        # CORS
        cors = result.get("cors", {})
        if cors.get("allow_origin"):
            origin = cors["allow_origin"]
            if origin == "*":
                print(f"    {Fore.RED}[!] CORS: Origin=* (open){Style.RESET_ALL}")
            else:
                print(f"    CORS: Origin={origin}")
            if cors.get("allow_credentials") == "true":
                print(f"    {Fore.RED}[!] CORS: credentials=true{Style.RESET_ALL}")

        # Tech hints
        for hint in result.get("tech_hints", set()):
            print(f"    {Fore.YELLOW}Tech: {hint}{Style.RESET_ALL}")

        # Interesting headers
        sec_headers = result.get("interesting_headers", {})
        for hdr in ("www-authenticate", "set-cookie", "x-debug", "x-request-id"):
            if hdr in sec_headers:
                val = sec_headers[hdr][:100]
                print(f"    {Fore.YELLOW}{hdr}: {val}{Style.RESET_ALL}")

        print()

    def _print_probe_summary(self):
        if not self.probe_results:
            print(f"\n  {Fore.RED}[!] No endpoints responded{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f" PROBE SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")

        total = len(self.probe_results)
        auth_count = sum(1 for r in self.probe_results if r["auth_required"])
        cors_open = sum(1 for r in self.probe_results if r.get("cors", {}).get("allow_origin") == "*")

        # Count methods across all endpoints
        method_counts = defaultdict(int)
        for r in self.probe_results:
            for m in r["methods"]:
                method_counts[m] += 1

        print(f"  Alive endpoints:   {total}")
        print(f"  Auth required:     {auth_count}")
        print(f"  Open CORS (*):     {cors_open}")
        print(f"  Method breakdown:")
        for m in self.METHODS:
            if method_counts[m]:
                color = self.METHOD_COLORS.get(m, Fore.WHITE)
                print(f"    {color}{m:8s}{Style.RESET_ALL} -> {method_counts[m]} endpoints")

        # Highlight juicy targets: endpoints accepting POST/PUT/DELETE with 200
        juicy = []
        for r in self.probe_results:
            for m in ("POST", "PUT", "DELETE", "PATCH"):
                info = r["methods"].get(m)
                if info and 200 <= info["status"] < 300:
                    juicy.append((r["endpoint"], m, info["status"]))

        if juicy:
            print(f"\n  {Fore.RED}[!] WRITABLE ENDPOINTS (accept POST/PUT/DELETE with 2xx):{Style.RESET_ALL}")
            for ep, method, status in juicy:
                color = self.METHOD_COLORS.get(method, Fore.WHITE)
                print(f"    {color}{method:7s}{Style.RESET_ALL} {ep}  -> {Fore.GREEN}{status}{Style.RESET_ALL}")

        # Collect all tech hints
        all_tech = set()
        for r in self.probe_results:
            all_tech.update(r.get("tech_hints", set()))
        if all_tech:
            print(f"\n  {Fore.YELLOW}Detected technologies:{Style.RESET_ALL}")
            for t in sorted(all_tech):
                print(f"    {t}")

    def get_json_results(self):
        out = []
        for r in self.probe_results:
            entry = {
                "endpoint": r["endpoint"],
                "url": r["url"],
                "methods": {},
                "auth_required": r["auth_required"],
                "cors": r.get("cors", {}),
                "tech": list(r.get("tech_hints", set())),
                "headers": r.get("interesting_headers", {}),
            }
            for m, info in r["methods"].items():
                entry["methods"][m] = {
                    "status": info["status"],
                    "content_type": info.get("content_type", ""),
                    "content_length": info.get("content_length", "?"),
                }
            out.append(entry)
        return out


class ReportGenerator:
    """Generates output reports in various formats."""

    @staticmethod
    def _ep_source_label(sources_map, ep):
        """Build a short source label for an endpoint showing which domain/file it came from."""
        srcs = []
        for src, eps in sources_map.items():
            if ep in eps:
                # Shorten: "https://school.cert.kz/_next/..." -> "school.cert.kz"
                # "inline:school.cert.kz#1" -> "school.cert.kz(inline)"
                # "chunk:abc.js" -> "chunk:abc.js"
                if src.startswith("http"):
                    host = urlparse(src).hostname or src
                    if host not in srcs:
                        srcs.append(host)
                elif src.startswith("inline:"):
                    tag = src.replace("inline:", "").split("#")[0]
                    label = f"{tag}(inline)" if tag else "inline"
                    if label not in srcs:
                        srcs.append(label)
                elif src.startswith("chunk:") or src.startswith("sourcemap:"):
                    if src not in srcs:
                        srcs.append(src)
                else:
                    if src not in srcs:
                        srcs.append(src)
        return ", ".join(srcs[:3]) if srcs else ""

    @staticmethod
    def print_results(analyzer, verbose=False):
        r = analyzer.results

        # Endpoints
        all_eps = set()
        for eps in r["endpoints"].values():
            all_eps.update(eps)

        if all_eps:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f" API ENDPOINTS & PATHS ({len(all_eps)} found)")
            print(f"{'='*60}{Style.RESET_ALL}")

            api_eps = sorted(e for e in all_eps if re.match(r"^/(?:api|v\d|graphql)", e))
            other_eps = sorted(e for e in all_eps if e not in api_eps and e.startswith("/"))
            full_urls = sorted(e for e in all_eps if e.startswith("http"))

            if api_eps:
                print(f"\n  {Fore.YELLOW}[API Endpoints]{Style.RESET_ALL}")
                for ep in api_eps:
                    src = ReportGenerator._ep_source_label(r["endpoints"], ep)
                    print(f"    {Fore.CYAN}{ep}{Style.RESET_ALL}  {Fore.WHITE}← {src}{Style.RESET_ALL}" if src else f"    {Fore.CYAN}{ep}{Style.RESET_ALL}")

            if other_eps:
                print(f"\n  {Fore.YELLOW}[Relative Paths]{Style.RESET_ALL}")
                for ep in other_eps:
                    src = ReportGenerator._ep_source_label(r["endpoints"], ep)
                    print(f"    {ep}  {Fore.WHITE}← {src}{Style.RESET_ALL}" if src else f"    {ep}")

            if full_urls:
                print(f"\n  {Fore.YELLOW}[Full URLs]{Style.RESET_ALL}")
                for ep in full_urls:
                    src = ReportGenerator._ep_source_label(r["endpoints"], ep)
                    print(f"    {Fore.BLUE}{ep}{Style.RESET_ALL}  {Fore.WHITE}← {src}{Style.RESET_ALL}" if src else f"    {Fore.BLUE}{ep}{Style.RESET_ALL}")

            if verbose:
                print(f"\n  {Fore.YELLOW}[By Source]{Style.RESET_ALL}")
                for src, eps in sorted(r["endpoints"].items()):
                    print(f"\n    {Fore.WHITE}{src}{Style.RESET_ALL}")
                    for ep in sorted(eps):
                        print(f"      {ep}")

        # Secrets
        all_secrets = []
        for entries in r["secrets"].values():
            all_secrets.extend(entries)

        if all_secrets:
            print(f"\n{Fore.RED}{'='*60}")
            print(f" SECRETS & CREDENTIALS ({len(all_secrets)} found)")
            print(f"{'='*60}{Style.RESET_ALL}")
            for sec in all_secrets:
                val_display = sec["value"][:80] + "..." if len(sec["value"]) > 80 else sec["value"]
                print(f"  {Fore.RED}[{sec['type']}]{Style.RESET_ALL}")
                print(f"    Value:  {Fore.YELLOW}{val_display}{Style.RESET_ALL}")
                print(f"    Source: {sec['source']}:{sec['line']}")
                print()

        # Sensitive Info
        all_sensitive = []
        for entries in r["sensitive"].values():
            all_sensitive.extend(entries)

        if all_sensitive:
            print(f"\n{Fore.MAGENTA}{'='*60}")
            print(f" SENSITIVE INFORMATION ({len(all_sensitive)} found)")
            print(f"{'='*60}{Style.RESET_ALL}")
            grouped = defaultdict(list)
            for s in all_sensitive:
                grouped[s["type"]].append(s)
            for stype, entries in sorted(grouped.items()):
                print(f"\n  {Fore.MAGENTA}[{stype}] ({len(entries)}){Style.RESET_ALL}")
                seen = set()
                for e in entries:
                    if e["value"] not in seen:
                        seen.add(e["value"])
                        print(f"    {e['value']}")

        # Domains — filter out known external noise
        if r["domains"]:
            filtered_domains = {d for d in r["domains"] if not JSAnalyzer._is_noise_domain(d)}
            if filtered_domains:
                print(f"\n{Fore.BLUE}{'='*60}")
                print(f" DISCOVERED DOMAINS ({len(filtered_domains)})")
                print(f"{'='*60}{Style.RESET_ALL}")
                for d in sorted(filtered_domains):
                    print(f"    {d}")

        # Endpoint -> Params mapping
        ep_params = r["endpoint_params"]
        if ep_params:
            print(f"\n{Fore.WHITE}{'='*60}")
            print(f" API REQUESTS ({len(ep_params)} endpoints)")
            print(f"{'='*60}{Style.RESET_ALL}")

            METHOD_COLOR = {
                "GET": Fore.GREEN, "POST": Fore.YELLOW, "PUT": Fore.BLUE,
                "DELETE": Fore.RED, "PATCH": Fore.MAGENTA,
            }
            for ep in sorted(ep_params.keys()):
                info = ep_params[ep]
                method = info["method"] or "?"
                params = sorted(info["params"])
                ct = info["content_type"]

                mc = METHOD_COLOR.get(method, Fore.WHITE)
                print(f"\n    {mc}{method:7s}{Style.RESET_ALL} {Fore.CYAN}{ep}{Style.RESET_ALL}")
                if ct:
                    print(f"            Content-Type: {ct}")
                print(f"            Params: {Fore.YELLOW}{', '.join(params)}{Style.RESET_ALL}")

        # Cloud URLs
        if r["cloud_urls"]:
            print(f"\n{Fore.YELLOW}{'='*60}")
            print(f" CLOUD RESOURCES ({len(r['cloud_urls'])})")
            print(f"{'='*60}{Style.RESET_ALL}")
            for c in sorted(r["cloud_urls"]):
                print(f"    {c}")

        # Summary
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f" SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Endpoints:    {len(all_eps)}")
        print(f"  Secrets:      {len(all_secrets)}")
        print(f"  Sensitive:    {len(all_sensitive)}")
        print(f"  Domains:      {len(r['domains'])}")
        print(f"  API Requests: {len(ep_params)}")
        print(f"  Cloud URLs:   {len(r['cloud_urls'])}")

    @staticmethod
    def save_json(analyzer, output_path, target, prober=None, target_analyzer=None, sub_collector=None, api_fuzzer=None):
        r = analyzer.results
        all_eps = set()
        for eps in r["endpoints"].values():
            all_eps.update(eps)

        data = {
            "target": target,
            "scan_date": datetime.now().isoformat(),
            "endpoints": {
                "api": sorted(e for e in all_eps if re.match(r"^/(?:api|v\d|graphql)", e)),
                "paths": sorted(e for e in all_eps if e.startswith("/") and not re.match(r"^/(?:api|v\d|graphql)", e)),
                "urls": sorted(e for e in all_eps if e.startswith("http")),
            },
            "secrets": [
                {"type": s["type"], "value": s["value"], "source": s["source"], "line": s["line"]}
                for entries in r["secrets"].values() for s in entries
            ],
            "sensitive": {
                stype: list({e["value"] for e in entries})
                for stype, entries in r["sensitive"].items()
            },
            "domains": sorted(r["domains"]),
            "api_requests": {
                ep: {"method": info["method"], "params": sorted(info["params"]), "content_type": info["content_type"]}
                for ep, info in r["endpoint_params"].items()
            },
            "cloud_urls": sorted(r["cloud_urls"]),
        }

        if prober:
            data["probe_results"] = prober.get_json_results()

        if target_analyzer:
            tr = target_analyzer.results
            data["target_analysis"] = {
                "tech": sorted(tr["tech"]),
                "missing_headers": tr["missing_headers"],
                "weak_headers": tr["weak_headers"],
                "info_leaks": tr["info_leaks"],
                "cookies": tr["cookies"],
                "cors": tr["cors"],
                "dangerous_methods": tr["dangerous_methods"],
            }

        if sub_collector and sub_collector.subdomains:
            data["subdomains"] = sorted(sub_collector.subdomains)
            data["alive"] = [
                {"url": a["url"], "status": a["status"], "title": a["title"],
                 "server": a["server"], "redirect": a["redirect"]}
                for a in sub_collector.alive
            ]
            if hasattr(sub_collector, "ip_map"):
                data["ip_pool"] = {
                    sub: sorted(ips) for sub, ips in sorted(sub_collector.ip_map.items())
                }
                data["ip_to_subs"] = {
                    ip: sorted(subs) for ip, subs in sorted(sub_collector.ip_to_subs.items())
                }

        if api_fuzzer and api_fuzzer.results:
            data["api_fuzz"] = api_fuzzer.get_json_results()

        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n{Fore.GREEN}[+] JSON report saved to: {output_path}{Style.RESET_ALL}")

    @staticmethod
    def save_endpoints_file(analyzer, output_path):
        all_eps = set()
        for eps in analyzer.results["endpoints"].values():
            all_eps.update(eps)
        with open(output_path, "w") as f:
            for ep in sorted(all_eps):
                f.write(ep + "\n")
        print(f"{Fore.GREEN}[+] Endpoints saved to: {output_path}{Style.RESET_ALL}")

    @staticmethod
    def save_wordlist(analyzer, output_path):
        """Generate a wordlist from discovered path segments."""
        words = set()
        for eps in analyzer.results["endpoints"].values():
            for ep in eps:
                parts = ep.strip("/").split("/")
                for part in parts:
                    clean = re.sub(r"[{}?\[\]#&=]", "", part)
                    if clean and len(clean) > 1 and not clean.isdigit():
                        words.add(clean)
        words.update(analyzer.results["parameters"])
        with open(output_path, "w") as f:
            for w in sorted(words):
                f.write(w + "\n")
        print(f"{Fore.GREEN}[+] Wordlist saved to: {output_path}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

_KNOWN_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int",
    "co", "io", "ai", "app", "dev", "me", "info", "biz", "name", "pro",
    "kz", "ru", "ua", "by", "kg", "uz", "tj", "tm", "az", "ge", "am", "md",
    "uk", "de", "fr", "it", "es", "nl", "be", "at", "ch", "pl", "cz", "se",
    "no", "dk", "fi", "pt", "gr", "ie", "ro", "hu", "bg", "hr", "sk", "si",
    "lt", "lv", "ee", "rs", "ba", "mk", "al", "me", "mt", "cy", "lu", "is",
    "cn", "jp", "kr", "in", "id", "th", "vn", "ph", "my", "sg", "tw", "hk",
    "au", "nz", "za", "ng", "ke", "eg", "ma", "tn", "gh", "et",
    "br", "mx", "ar", "cl", "co", "pe", "ve", "ec", "uy", "py",
    "ca", "us", "tr", "il", "sa", "ae", "qa", "kw", "bh", "om", "jo", "lb",
    "eu", "asia", "club", "online", "site", "store", "tech", "xyz", "top",
}


def _extract_root_domain(hostname):
    """Extract root domain from hostname: portalarek.energy.kz -> energy.kz"""
    if not hostname:
        return hostname
    parts = hostname.lower().split(".")
    if len(parts) <= 2:
        return hostname
    # Handle two-part TLDs: co.uk, com.au, co.kz, etc.
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "edu", "ac"):
        return ".".join(parts[-3:])
    # Standard: take last 2 parts if TLD is known
    if parts[-1] in _KNOWN_TLDS:
        return ".".join(parts[-2:])
    return hostname


def _is_html_heavy(text):
    """Return True if inline script is mostly HTML/SVG markup, not real JS."""
    html_chars = sum(1 for m in re.finditer(r'<[a-zA-Z/]', text))
    svg_paths = len(re.findall(r'\bd="[^"]{100,}"', text))
    lines = max(text.count('\n'), 1)
    if svg_paths > 0:
        return True
    if html_chars / lines > 3:
        return True
    return False


def process_js(url_or_path, fetcher, analyzer, deep_analyzer=None, is_file=False):
    """Process a single JS source."""
    source_name = os.path.basename(url_or_path) if is_file else url_or_path

    if is_file:
        content = fetcher.read_file(url_or_path)
    else:
        content = fetcher.fetch_url(url_or_path)

    if not content:
        return

    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Analyzing: {source_name} ({len(content)} bytes)")
    analyzer.extract_all(content, source_name)

    if deep_analyzer and not is_file:
        # Webpack chunks
        chunks = deep_analyzer.find_webpack_chunks(content, url_or_path)
        if chunks:
            print(f"    {Fore.YELLOW}[*] Found {len(chunks)} webpack chunks{Style.RESET_ALL}")
            for chunk_url in chunks:
                chunk_content = fetcher.fetch_url(chunk_url)
                if chunk_content:
                    cname = os.path.basename(urlparse(chunk_url).path)
                    print(f"    {Fore.GREEN}[+]{Style.RESET_ALL} Chunk: {cname} ({len(chunk_content)} bytes)")
                    analyzer.extract_all(chunk_content, f"chunk:{cname}")

        # Source maps
        maps = deep_analyzer.find_sourcemaps(content, url_or_path)
        for smap in maps:
            print(f"    {Fore.YELLOW}[*] Fetching source map: {smap}{Style.RESET_ALL}")
            src_content = deep_analyzer.fetch_sourcemap(smap)
            if src_content:
                print(f"    {Fore.GREEN}[+]{Style.RESET_ALL} Source map content: {len(src_content)} bytes")
                analyzer.extract_all(src_content, f"sourcemap:{os.path.basename(smap)}")


def run(args):
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print(BANNER)

    fetcher = JSFetcher(
        timeout=args.timeout,
        proxy=args.proxy,
    )
    if args.headers:
        for h in args.headers:
            key, val = h.split(":", 1)
            fetcher.session.headers[key.strip()] = val.strip()

    if args.cookies:
        for c in args.cookies:
            key, val = c.split("=", 1)
            fetcher.session.cookies.set(key.strip(), val.strip())

    analyzer = JSAnalyzer(base_url=args.url or "")
    deep = DeepAnalyzer(fetcher) if args.deep else None

    js_targets = []

    # Single URL mode
    if args.url:
        url = args.url
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
            args.url = url
        parsed = urlparse(url)
        if parsed.path.endswith(".js"):
            js_targets.append(url)
        else:
            print(f"{Fore.CYAN}[*] Crawling {url} for JS files...{Style.RESET_ALL}")
            discovered = fetcher.discover_js_urls(url)
            js_targets.extend(discovered)
            print(f"{Fore.GREEN}[+] Found {len(discovered)} JS files{Style.RESET_ALL}")

            # Also analyze inline scripts on the page
            page_content = fetcher.fetch_url(url)
            if page_content:
                soup = BeautifulSoup(page_content, "html.parser")
                for i, script in enumerate(soup.find_all("script", src=False)):
                    if script.string and len(script.string.strip()) > 50 and not _is_html_heavy(script.string):
                        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Inline script #{i+1} ({len(script.string)} bytes)")
                        analyzer.extract_all(script.string, f"inline:script#{i+1}")

    # File list mode — each URL gets crawled for JS (same as -u)
    if args.file:
        with open(args.file) as f:
            file_urls = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
        print(f"{Fore.CYAN}[*] Processing {len(file_urls)} URLs from {args.file}...{Style.RESET_ALL}")
        for line in file_urls:
            if not line.startswith(("http://", "https://")):
                line = f"https://{line}"
            if line.startswith("http"):
                parsed_line = urlparse(line)
                if parsed_line.path.endswith(".js"):
                    js_targets.append(line)
                else:
                    print(f"  {Fore.CYAN}[*] Crawling {line}...{Style.RESET_ALL}")
                    discovered = fetcher.discover_js_urls(line)
                    js_targets.extend(discovered)
                    print(f"  {Fore.GREEN}[+] {len(discovered)} JS files{Style.RESET_ALL}")
                    page_content = fetcher.fetch_url(line)
                    if page_content:
                        soup = BeautifulSoup(page_content, "html.parser")
                        for i, script in enumerate(soup.find_all("script", src=False)):
                            if script.string and len(script.string.strip()) > 50 and not _is_html_heavy(script.string):
                                analyzer.extract_all(script.string, f"inline:{parsed_line.netloc}#{i+1}")
            else:
                js_targets.append(("file", line))

    # Directory mode
    if args.directory:
        for root, dirs, files in os.walk(args.directory):
            for fname in files:
                if fname.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".map")):
                    js_targets.append(("file", os.path.join(root, fname)))

    print(f"\n{Fore.CYAN}[*] Processing {len(js_targets)} JS targets with {args.threads} threads...{Style.RESET_ALL}\n")

    def process_target(target):
        if isinstance(target, tuple) and target[0] == "file":
            process_js(target[1], fetcher, analyzer, deep, is_file=True)
        else:
            process_js(target, fetcher, analyzer, deep)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        pool.map(process_target, js_targets)

    # Print JS analysis results
    ReportGenerator.print_results(analyzer, verbose=args.verbose)

    # Auto-run target analysis when URL given
    target_analyzer = None
    sub_collector = None
    prober = None
    api_fuzzer = None

    if args.url:
        parsed_target = urlparse(args.url)
        target_host = parsed_target.hostname
        base_domain = _extract_root_domain(target_host)

        # Security headers, cookies, CORS, tech (main target + alive subdomains)
        print(f"\n{Fore.CYAN}[*] Analyzing target headers & security...{Style.RESET_ALL}")
        target_analyzer = TargetAnalyzer(fetcher)
        target_analyzer.analyze(args.url)
        target_analyzer.print_results()

        # Check dangerous methods on alive subdomains after subdomain enum (added below)

        # Subdomain enumeration + alive check
        if base_domain:
            if base_domain != target_host:
                print(f"\n{Fore.CYAN}[*] Target: {target_host} → root domain: {base_domain}{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}[*] Enumerating subdomains for {base_domain}...{Style.RESET_ALL}")
            sub_collector = SubdomainCollector(fetcher, threads=args.threads)
            sub_collector.enumerate(base_domain)
            sub_collector.from_domains(analyzer.results["domains"], base_domain)
            print(f"{Fore.GREEN}[+] Total unique subdomains: {len(sub_collector.subdomains)}{Style.RESET_ALL}")
            sub_collector.resolve_ips()
            sub_collector.check_alive()
            sub_collector.print_results()

            # Check dangerous methods on alive subdomains (only 200 OK, skip main target already checked)
            alive_200 = [a for a in sub_collector.alive if a.get("status") == 200 and a["subdomain"] != target_host]
            if alive_200:
                seen_subs = set()
                for a in alive_200:
                    sub = a["subdomain"]
                    if sub in seen_subs:
                        continue
                    seen_subs.add(sub)
                    for method in ["TRACE", "PUT", "DELETE"]:
                        try:
                            r3 = fetcher.session.request(method, a["url"], timeout=fetcher.timeout, verify=False)
                            if r3.status_code not in (405, 501, 400, 403, 404, 301, 302, 307, 308):
                                target_analyzer.results["dangerous_methods"].append({"method": method, "status": r3.status_code, "url": a["url"]})
                        except requests.RequestException:
                            pass
                # Reprint if new methods found
                sub_dangerous = [dm for dm in target_analyzer.results["dangerous_methods"] if dm.get("url") != args.url]
                if sub_dangerous:
                    print(f"\n{Fore.RED}{'='*60}")
                    print(f" DANGEROUS HTTP METHODS (subdomains)")
                    print(f"{'='*60}{Style.RESET_ALL}")
                    for dm in sub_dangerous:
                        print(f"    {Fore.RED}{dm['method']}{Style.RESET_ALL} -> {dm['status']}  {Fore.WHITE}@ {dm['url']}{Style.RESET_ALL}")

            # API fuzzing on alive hosts
            api_fuzzer = None
            if sub_collector.alive:
                api_fuzzer = APIFuzzer(fetcher, threads=min(args.threads * 3, 40))
                api_fuzzer.fuzz_alive(sub_collector.alive)
                api_fuzzer.print_results()

            # Deep: scan alive subdomains for JS too (only 200 OK, skip error pages)
            if args.deep and sub_collector.alive:
                alive_urls = [a["url"] for a in sub_collector.alive if a["subdomain"] != target_host and a.get("status") == 200]
                if alive_urls:
                    print(f"\n{Fore.CYAN}[*] Deep scanning {len(alive_urls)} alive subdomains for JS...{Style.RESET_ALL}")
                    sub_js = []
                    for alive_url in alive_urls:
                        print(f"  {Fore.CYAN}[*] Crawling {alive_url}...{Style.RESET_ALL}")
                        discovered = fetcher.discover_js_urls(alive_url)
                        sub_js.extend(discovered)
                        print(f"  {Fore.GREEN}[+] {len(discovered)} JS files{Style.RESET_ALL}")
                        page_content = fetcher.fetch_url(alive_url)
                        if page_content:
                            soup = BeautifulSoup(page_content, "html.parser")
                            host = urlparse(alive_url).hostname
                            for i, script in enumerate(soup.find_all("script", src=False)):
                                if script.string and len(script.string.strip()) > 50 and not _is_html_heavy(script.string):
                                    analyzer.extract_all(script.string, f"inline:{host}#{i+1}")
                    if sub_js:
                        print(f"\n{Fore.CYAN}[*] Analyzing {len(sub_js)} JS files from subdomains...{Style.RESET_ALL}")
                        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
                            pool.map(lambda t: process_js(t, fetcher, analyzer, deep), sub_js)
                        print(f"\n{Fore.CYAN}[*] Updated results after subdomain scan:{Style.RESET_ALL}")
                        ReportGenerator.print_results(analyzer, verbose=args.verbose)

        # Probe endpoints
        if args.probe:
            all_eps = set()
            for eps in analyzer.results["endpoints"].values():
                all_eps.update(eps)
            probe_targets = {e for e in all_eps if e.startswith("/")}
            if probe_targets:
                probe_base = f"{parsed_target.scheme}://{parsed_target.netloc}"
                prober = APIProber(fetcher, probe_base, threads=args.probe_threads)
                prober.probe_endpoints(probe_targets)
            else:
                print(f"\n{Fore.YELLOW}[*] No relative endpoints to probe{Style.RESET_ALL}")

    # Save outputs
    if args.output:
        ReportGenerator.save_json(
            analyzer, args.output, args.url or args.file or args.directory,
            prober=prober, target_analyzer=target_analyzer, sub_collector=sub_collector,
            api_fuzzer=api_fuzzer,
        )
    if args.endpoints_out:
        ReportGenerator.save_endpoints_file(analyzer, args.endpoints_out)
    if args.wordlist:
        ReportGenerator.save_wordlist(analyzer, args.wordlist)

    # Auto-save subdomain files when -o is used
    if sub_collector and args.output:
        base = args.output.rsplit(".", 1)[0] if "." in args.output else args.output
        sub_collector.save_subs(base + "_subs.txt")
        sub_collector.save_alive(base + "_alive.txt")


def main():
    signal.signal(signal.SIGINT, lambda s, f: (print(f"\n{Fore.RED}[!] Interrupted{Style.RESET_ALL}"), sys.exit(1)))

    parser = argparse.ArgumentParser(
        prog="webrecon",
        description=f"WebRecon v{VERSION} — Web Recon Toolkit for Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Features:
  JS analysis       Extract endpoints, secrets, API keys from JavaScript
  Subdomain enum    Passive enum via crt.sh, hackertarget, rapiddns, urlscan, OTX
  Alive check       HTTP probe on 80, 443 + 21 common web ports
  API fuzzing       Auto-fuzz common paths on alive hosts
  Security audit    Headers, cookies, CORS, dangerous methods, tech detection
  Deep mode         Webpack chunks, source maps, subdomain JS crawl
  Endpoint probe    Check methods, CORS, auth on discovered endpoints

Examples:
  %(prog)s -u https://example.com                      Full recon: JS + subs + fuzz
  %(prog)s -u https://example.com --deep               + webpack chunks, source maps
  %(prog)s -u https://example.com --deep --probe       + probe every endpoint
  %(prog)s -u https://sub.example.com                  Auto-detects root domain
  %(prog)s -f urls.txt                                 Batch scan from file
  %(prog)s -u https://example.com -o report.json       Save full JSON report
        """,
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument("-u", "--url", help="Target URL (page or JS file)")
    input_group.add_argument("-f", "--file", help="File containing URLs (one per line)")
    input_group.add_argument("-d", "--directory", help="Local directory of JS files")

    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--deep", action="store_true", help="Deep mode: webpack chunks + source maps")
    scan_group.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads (default: 10)")
    scan_group.add_argument("--timeout", type=int, default=15, help="HTTP timeout seconds (default: 15)")
    scan_group.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    scan_group.add_argument("-H", "--headers", action="append", help="Custom header (e.g. -H 'Auth: token')")
    scan_group.add_argument("-c", "--cookies", action="append", help="Cookie (e.g. -c 'session=abc123')")
    scan_group.add_argument("--probe", action="store_true", help="Probe endpoints: check accepted methods, CORS, tech, response info")
    scan_group.add_argument("--probe-threads", type=int, default=5, help="Threads for probing (default: 5)")
    scan_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show per-source results)")

    output_group = parser.add_argument_group("Output")
    output_group.add_argument("-o", "--output", help="Save JSON report to file")
    output_group.add_argument("-e", "--endpoints-out", help="Save endpoints to text file")
    output_group.add_argument("-w", "--wordlist", help="Generate path wordlist from findings")

    args = parser.parse_args()

    if not any([args.url, args.file, args.directory]):
        parser.print_help()
        sys.exit(1)

    run(args)


if __name__ == "__main__":
    main()
