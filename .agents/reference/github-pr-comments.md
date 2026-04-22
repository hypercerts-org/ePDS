# PR Review Comments API

To read and reply to review comments (CodeRabbit, etc.) on a PR:

```bash
# List all review comments
gh api repos/hypercerts-org/ePDS/pulls/<N>/comments --jq '.[] | {id, path: .path, line: .line}'

# Read a specific comment (NOTE: no PR number in this endpoint)
gh api repos/hypercerts-org/ePDS/pulls/comments/<ID> --jq '.body'

# Reply to a comment
gh api repos/hypercerts-org/ePDS/pulls/<N>/comments -F in_reply_to=<ID> -f body="..."
```

**Important:** The individual comment endpoint is `/pulls/comments/<ID>` — it
does NOT include the PR number. Using `/pulls/<N>/comments/<ID>` returns 404.

Check for and address unresolved review comments after every push.
