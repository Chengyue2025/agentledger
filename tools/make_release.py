import os, re, json, urllib.request

token = os.environ["GH_TOKEN"]
src = open("CHANGELOG.md", encoding="utf-8").read()
m = re.search(r"## \[0\.4\.0\].*?(?=\n## \[0\.3\.0\])", src, re.S)
body = m.group(0).strip() if m else "See CHANGELOG.md"
body += ("\n\n**Verification**: 251 tests pass (py -m unittest discover -s tests); "
         "audit-share fixtures verified (BLOCK/0 and CLEAR/100 for both share and "
         "plugin forms); DSH plugin conformance suite: 27/27.")
body += "\n\n**Full changelog**: https://github.com/Chengyue2025/agentledger/blob/main/CHANGELOG.md"

payload = json.dumps({
    "tag_name": "v0.4.0",
    "target_commitish": "main",
    "name": "v0.4.0 - ES256/JCS/JWS receipts (IETF draft -13), GB/Z 185 export, demo fixtures, BOM fix",
    "body": body,
    "draft": False,
    "prerelease": False,
}).encode("utf-8")

req = urllib.request.Request(
    "https://api.github.com/repos/Chengyue2025/agentledger/releases",
    data=payload, method="POST",
    headers={"Authorization": f"token {token}",
             "Accept": "application/vnd.github+json",
             "Content-Type": "application/json",
             "User-Agent": "agentledger-release"})
try:
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read())
        print("RELEASE CREATED:", d["tag_name"], "|", d["html_url"])
except urllib.error.HTTPError as e:
    print("HTTP", e.code, e.read().decode()[:300])
